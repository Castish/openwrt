#!/usr/bin/env python3
"""Actual ARM execution with bounded UART, FE and GICv2 register models.
The model verifies access scope/order/cleanup, not physical IRQ wiring.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_PROT_READ, UC_PROT_EXEC, UC_HOOK_CODE
from unicorn.arm_const import (
    UC_CPU_ARM_CORTEX_A7, UC_ARM_REG_CPSR, UC_ARM_REG_PC, UC_ARM_REG_R0,
    UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_R4, UC_ARM_REG_R5,
    UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_R8, UC_ARM_REG_R9,
    UC_ARM_REG_R10, UC_ARM_REG_R11, UC_ARM_REG_R12,
)
ROOT=Path(__file__).resolve().parent
PAYLOAD=(ROOT/'c80-irq-probe-v2.bin').read_bytes()
UART,FE,GIC,GICC=0x11002000,0x1B100000,0x10310000,0x10320000
STACK,RETURN=0x41FE0000,0x41F00000
PRESERVED=[UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,
           UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11,
           UC_ARM_REG_R12,UC_ARM_REG_SP,UC_ARM_REG_LR]
MODES=[0]+[1]*4+[2]*4+[3]
MASKS=[0,0,1,0x10000,0,0,1,0x10000,0,0]

def run_case(name, *, address=0x40230000, cpsr=0x600001D3, midr=0x410FC073,
             mpidr=0x80000000, cfg=0x1410, initial_mask=0, ctlr=0,
             typer=0xFC68, spi_enabled=False, cpu_mask=1, edge=False,
             status=0x10001, routing='grouping', implemented_ctlr=3,
             uart='ready', fault=None, expected_guard=0, expected_restore=0,
             original_fe=(0,0,0), groups_nonzero=False):
    cpu=Uc(UC_ARCH_ARM,UC_MODE_ARM)
    cpu.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A7)
    cpu.mem_map(address,4096)
    cpu.mem_write(address,PAYLOAD)
    cpu.mem_protect(address,4096,UC_PROT_READ|UC_PROT_EXEC)
    cpu.mem_map(STACK,4096)
    cpu.mem_map(RETURN,4096,UC_PROT_READ|UC_PROT_EXEC)
    cpu.reg_write(UC_ARM_REG_CPSR,cpsr)
    original_cpsr=cpu.reg_read(UC_ARM_REG_CPSR)
    sentinels={reg:0x45000000+i*0x100 for i,reg in enumerate(PRESERVED)}
    sentinels[UC_ARM_REG_SP]=STACK+4096
    sentinels[UC_ARM_REG_LR]=RETURN
    for reg,value in sentinels.items(): cpu.reg_write(reg,value)
    state={'ctlr':ctlr,'enables':[0xFFFF]+[0]*8,
           'targets':[int.from_bytes(bytes((i*4+j)%16 for j in range(4)),'little') for i in range(64)],
           'fe':{0xA04:cfg,0xA20:status,0xA28:initial_mask,
                 0x20:original_fe[0],0xA50:original_fe[1],0xA54:original_fe[2]}}
    if spi_enabled: state['enables'][7]=0x10000
    original=deepcopy(state)
    config=[0xAAAAAAAA,0x55540000]+[0x55555555]*16
    if edge: config[8]|=2
    group=[0xAAAAAAAA if groups_nonzero else 0]*9
    output=bytearray()
    writes=[]
    uart_reads=0
    target_write_count=0
    if routing=='different-ids': routes={1:184,0x10000:189}
    else: routes={1:255,0x10000:256}

    def pending_values():
        values=[0]*9
        if not state['ctlr']: return values
        # An unrelated asserted peripheral must not be attributed to PDMA.
        if state['enables'][2]&2: values[2]|=2
        configured=(state['fe'][0x20],state['fe'][0xA50],state['fe'][0xA54])==(0x21021000,1,0x10000)
        if routing=='none' or (routing=='grouping' and not configured): return values
        for bit,hwirq in routes.items():
            word=hwirq//32
            target=(state['targets'][(hwirq-32)//4]>>((hwirq%4)*8))&255
            if (state['fe'][0xA28]&status&bit and state['enables'][word]&(1<<(hwirq%32)) and target&cpu_mask):
                values[word]|=1<<(hwirq%32)
        return values

    def read_fe(uc,off,size,data):
        assert size==4 and off in state['fe'],('unexpected FE read',hex(off))
        return state['fe'][off]
    def write_fe(uc,off,size,value,data):
        assert size==4 and expected_guard in (0,11)
        assert cpu.reg_read(UC_ARM_REG_CPSR)&255==0xD3
        assert off in {0x20,0xA28,0xA50,0xA54},('unexpected FE write',hex(off))
        if off==0xA28: assert value in {0,1,0x10000}
        else:
            allowed={0x20:0x21021000,0xA50:1,0xA54:0x10000}
            assert value in {allowed[off],original['fe'][off]}
            assert state['fe'][0xA28]==0
        writes.append((FE+off,value))
        if fault=='fe-group-restore' and off==0x20 and value==original['fe'][off]: return
        state['fe'][off]=value
    def read_gic(uc,off,size,data):
        assert size==4 and off%4==0
        if off==0: return state['ctlr']
        if off==4: return typer
        if 0x80<=off<0xA4: return group[(off-0x80)//4]
        if 0x100<=off<0x124: return state['enables'][(off-0x100)//4]
        if 0x200<=off<0x224: return pending_values()[(off-0x200)//4]
        if 0x800<=off<0x820: return cpu_mask*0x01010101
        if 0x820<=off<0x920: return state['targets'][(off-0x820)//4]
        if 0xC00<=off<0xC48: return config[(off-0xC00)//4]
        raise AssertionError(('unexpected GIC read',hex(off)))
    def write_gic(uc,off,size,value,data):
        nonlocal target_write_count
        assert size==4 and expected_guard in (0,11)
        assert cpu.reg_read(UC_ARM_REG_CPSR)&255==0xD3
        writes.append((GIC+off,value))
        if off==0:
            assert value in {0,3}
            if value==3:
                assert state['targets']==[cpu_mask*0x01010101]*64
                assert state['enables'][1:]==[0xFFFFFFFF]*8
            state['ctlr']=value&implemented_ctlr
        elif 0x104<=off<0x124:
            assert state['ctlr']==0 and value==0xFFFFFFFF
            state['enables'][(off-0x100)//4]|=value
        elif 0x184<=off<0x1A4:
            assert state['ctlr']==0 and value==0xFFFFFFFF
            index=(off-0x180)//4
            if not (fault=='spi-enable-restore' and index==7):
                state['enables'][index]&=~value&0xFFFFFFFF
        elif 0x820<=off<0x920:
            assert state['ctlr']==0
            # In fault injection a failed ICENABLER is deliberately visible.
            if fault!='spi-enable-restore': assert state['enables'][1:]==[0]*8
            index=(off-0x820)//4
            expected=cpu_mask*0x01010101 if target_write_count<64 else original['targets'][index]
            assert value==expected
            target_write_count+=1
            if not ((fault=='target-restore' and target_write_count==82) or
                    (fault=='target-setup' and target_write_count==18)):
                state['targets'][index]=value
        else: raise AssertionError(('unallowed GIC write',hex(off)))
    def read_gicc(uc,off,size,data):
        assert size==4 and off in {0,4}
        return 0 if off==0 else 0xF0
    def write_gicc(uc,off,size,value,data):
        raise AssertionError('CPU interface must be read-only')
    def assert_cleanup_before_uart():
        assert state['ctlr']==original['ctlr']
        assert state['fe'][0xA28]==initial_mask
        assert state['fe'][0xA04]==cfg and state['fe'][0xA20]==status
        for off in [0x20,0xA50,0xA54]:
            if fault=='fe-group-restore' and off==0x20: continue
            assert state['fe'][off]==original['fe'][off]
        if fault!='target-restore': assert state['targets']==original['targets']
        if fault!='spi-enable-restore': assert state['enables']==original['enables']
        # Every normal mutation/cleanup must finish before even a failed THRE poll.
        if expected_guard==0: assert len(writes)==161
        elif expected_guard==11: assert len(writes)==141
        else: assert not writes
    def read_uart(uc,off,size,data):
        nonlocal uart_reads
        assert off==0x14 and size==4
        assert_cleanup_before_uart()
        uart_reads+=1
        if uart=='timeout' or (uart=='late-timeout' and len(output)>=100): return 0
        return 0x20 if uart!='delayed' or uart_reads%3==0 else 0
    def write_uart(uc,off,size,value,data):
        assert off==0 and size==4 and value<256
        assert_cleanup_before_uart()
        output.append(value)

    for instruction,value in [(bytes.fromhex('100f10ee'),midr),(bytes.fromhex('b00f10ee'),mpidr)]:
        matches=[address+i for i in range(0,len(PAYLOAD),4) if PAYLOAD[i:i+4]==instruction]
        assert len(matches)==1
        def emulate_cp_id(uc,pc,size,data,value=value):
            assert size==4
            uc.reg_write(UC_ARM_REG_R0,value)
            uc.reg_write(UC_ARM_REG_PC,pc+4)
        cpu.hook_add(UC_HOOK_CODE,emulate_cp_id,begin=matches[0],end=matches[0])
    cpu.mmio_map(UART,4096,read_uart,None,write_uart,None)
    cpu.mmio_map(FE,4096,read_fe,None,write_fe,None)
    cpu.mmio_map(GIC,4096,read_gic,None,write_gic,None)
    cpu.mmio_map(GICC,4096,read_gicc,None,write_gicc,None)
    cpu.emu_start(address,RETURN,count=12_000_000)
    assert cpu.reg_read(UC_ARM_REG_PC)==RETURN
    for reg,value in sentinels.items(): assert cpu.reg_read(reg)==value,reg
    assert cpu.reg_read(UC_ARM_REG_CPSR)&0x3FF==original_cpsr&0x3FF
    assert bytes(cpu.mem_read(address,len(PAYLOAD)))==PAYLOAD
    assert_cleanup_before_uart()
    expected_rc=1 if 'timeout' in uart else (64 if expected_restore else expected_guard)
    assert cpu.reg_read(UC_ARM_REG_R0)==expected_rc
    if uart=='timeout': assert len(output)==0 and uart_reads==1_000_000
    elif uart=='late-timeout': assert len(output)==100 and uart_reads==1_000_100
    else:
        text=output.decode('ascii')
        assert text.startswith('\r\nC80 IRQ route probe v2\r\n') and text.endswith('DONE\r\n')
        values={k:int(v,16) for k,v in re.findall(r'^([A-Z0-9_]+)=([0-9a-f]{8})\r?$',text,re.M)}
        assert len(values)==32,values
        expected_fields={'CPSR_BEFORE':original_cpsr,'MIDR':midr,'MPIDR':mpidr,
                         'GICD_CTLR_BEFORE':ctlr,'GICD_TYPER':typer,'GICC_CTLR':0,'GICC_PMR':0xF0,
                         'PDMA_CFG_BEFORE':cfg,'PDMA_CFG_AFTER':cfg,
                         'PDMA_STATUS_BEFORE':status,'PDMA_STATUS_AFTER':status,
                         'PDMA_MASK_BEFORE':initial_mask,'PDMA_MASK_AFTER':initial_mask,
                         'FE_GROUP_BEFORE':original_fe[0],'PDMA_GROUP0_BEFORE':original_fe[1],
                         'PDMA_GROUP1_BEFORE':original_fe[2],'CPU_TARGET_MASK':cpu_mask,
                         'TARGET_TEST_MISMATCHES':1 if fault=='target-setup' else 0,'GUARD_RC':expected_guard,
                         'RESTORE_ERRORS':expected_restore,'GICD_CTLR_AFTER':ctlr,
                         'FE_GROUP_AFTER':state['fe'][0x20],'PDMA_GROUP0_AFTER':state['fe'][0xA50],
                         'PDMA_GROUP1_AFTER':state['fe'][0xA54],
                         'TARGET_RESTORE_MISMATCHES':1 if fault=='target-restore' else 0,
                         'SPI_ENABLE_RESTORE_MISMATCHES':1 if fault=='spi-enable-restore' else 0}
        if expected_guard==0:
            expected_fields.update({'GICD_CTLR_ENABLED':3&implemented_ctlr,
                                    'FE_GROUP_TEST_RB':0x21021000,'PDMA_GROUP0_TEST_RB':1,
                                    'PDMA_GROUP1_TEST_RB':0x10000,'SPI_ENABLE_TEST_AND':0xFFFFFFFF})
        for k,v in expected_fields.items(): assert values[k]==v,(name,k,values[k],v)
        assert values['CPSR_AFTER']&0x3FF==original_cpsr&0x3FF
        for label,expected in [('ENABLE_BEFORE',original['enables']),('CONFIG_BEFORE',config),('GROUP_BEFORE',group)]:
            m=re.search(r'^'+label+r'=(.*?)\r?$',text,re.M)
            assert m and [int(w,16) for w in m[1].split()]==expected
        samples=re.findall(r'^MODE=([0-9a-f]{8}) MASK=([0-9a-f]{8}) READBACK=([0-9a-f]{8}) '
                           r'STATUS=([0-9a-f]{8}) GICD=([0-9a-f]{8})\r?\nPENDING=(.*?)\r?$',text,re.M)
        assert len(samples)==(1 if expected_guard else 10)
        for i,(mode,requested,readback,ps,gicd,raw) in enumerate(samples):
            mode,requested,readback,ps,gicd=map(lambda s:int(s,16),(mode,requested,readback,ps,gicd))
            assert mode==(0 if expected_guard else MODES[i])
            assert requested==(initial_mask if expected_guard else MASKS[i])
            assert readback==requested and ps==status
            assert gicd==(ctlr if mode in {0,3} else 3&implemented_ctlr)
            observed=[int(w,16) for w in raw.split()]
            assert len(observed)==9
            if not expected_guard:
                predicted=[0]*9
                if mode in {1,2}:
                    predicted[2]|=2
                    configured=mode==2 or original_fe==(0x21021000,1,0x10000)
                    if routing!='none' and (routing!='grouping' or configured):
                        for bit,hwirq in routes.items():
                            if status&requested&bit: predicted[hwirq//32]|=1<<(hwirq%32)
                assert observed==predicted,(name,mode,requested,observed,predicted)
        if name=='grouping-required': (ROOT/'example-emulated-output.txt').write_text(text,newline='')
    return {'name':name,'load_address':hex(address),'guard_rc':expected_guard,
            'restore_errors_detected':expected_restore,'return_code':expected_rc,
            'external_writes':len(writes),'uart_reads':uart_reads,'uart_bytes':len(output),
            'cleanup_checked_before_uart':True,'abi_code_cpu_control_unchanged':True,
            'dma_flash_gicc_trigger_security_priority_status_ack_writes':False}

cases=[
    run_case('grouping-required'),
    run_case('inherited-grouping-already-routes',routing='inherited'),
    run_case('different-ids-discovered-without-hardcoding',routing='different-ids'),
    run_case('no-visible-routing',routing='none'),
    run_case('one-visible-gic-control-enable-bit',implemented_ctlr=1),
    run_case('relocation-delayed-uart',address=0x40240000,uart='delayed'),
    run_case('different-current-cpu-target',cpu_mask=4,mpidr=0x80000002),
    run_case('nonzero-original-grouping-restored',original_fe=(0x123400,0x20,0x4000)),
    run_case('group-registers-read-only',groups_nonzero=True),
    run_case('guard-irq-enabled',cpsr=0x13,expected_guard=2),
    run_case('guard-fiq-enabled',cpsr=0x93,expected_guard=2),
    run_case('guard-active-dma',cfg=0x1455,expected_guard=3),
    run_case('guard-busy-dma',cfg=0x141A,expected_guard=3),
    run_case('guard-nonzero-pdma-mask',initial_mask=1,expected_guard=4),
    run_case('guard-other-gic-size',typer=0xFC67,expected_guard=5),
    run_case('guard-other-cpu-part',midr=0x410FC090,expected_guard=6),
    run_case('guard-other-implementer',midr=0x420FC073,expected_guard=6),
    run_case('guard-distributor-already-enabled',ctlr=1,expected_guard=7),
    run_case('guard-spi-already-enabled',spi_enabled=True,expected_guard=8),
    run_case('guard-no-cpu-target',cpu_mask=0,expected_guard=9),
    run_case('guard-multiple-cpu-targets',cpu_mask=3,expected_guard=9),
    run_case('guard-edge-spi',edge=True,expected_guard=10),
    run_case('guard-missing-latched-rx',status=1,expected_guard=12),
    run_case('target-setup-write-ignored-aborts-before-enabling',fault='target-setup',expected_guard=11),
    run_case('target-restore-failure-detected',fault='target-restore',expected_restore=64),
    run_case('spi-enable-restore-failure-detected',fault='spi-enable-restore',expected_restore=128),
    run_case('fe-group-restore-failure-detected',fault='fe-group-restore',expected_restore=4),
    run_case('uart-down-after-cleanup',uart='timeout'),
    run_case('uart-fails-mid-output-after-cleanup',uart='late-timeout'),
]
report={'binary_bytes':len(PAYLOAD),'binary_sha256':hashlib.sha256(PAYLOAD).hexdigest(),
        'cases_passed':len(cases),'scope':'actual ARM binary in Cortex-A7 Unicorn; CP15 IDs injected, GIC/FE/UART modeled; hardware IRQ wiring and MMIO/cache timing unverified',
        'cases':cases}
(ROOT/'verification.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:report[k] for k in ['binary_bytes','binary_sha256','cases_passed']},indent=2))
