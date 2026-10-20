#!/usr/bin/env python3
"""Run actual ARM code with strict CP15/AON/CONNSYS/MCU models.

Full-success executes real C CRC/copy and the actual ARM cache-loop/ATS
instruction paths. CP15 results/cache effects/MCU execution are modeled;
no real MMU, cache visibility, RF, power or peripheral bus is emulated.
Fault runs use host CRC/copy substitutions unless --full-only is selected.
Those substitutions are explicitly recorded, not presented as execution.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import struct
import time
import zlib
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.arm_const import *

root=Path(__file__).resolve().parent
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--full-only',action='store_true')
parser.add_argument('--fast-only',action='store_true')
options=parser.parse_args()
assert not (options.full_only and options.fast_only)
payload=(root/'c80-connsys-bootstrap.bin').read_bytes()
symbols={n:int(a,16) for a,_,n in (l.split() for l in (root/'symbols.txt').read_text().splitlines())}
AON={int(a,16):int(v,16) for a,v in json.loads((root/'baseline.json').read_text())['registers'].items()}
BASE,EMI,BACKUP,EMI_SIZE=0x41000000,0x40000000,0x41050000,0x200000
UART,RESET,COMPLETE=0x11002000,0x10212018,0x18002600
CTRL=(0x18002150,0x18001130,0x10210000)
MASKS=(0x208001,1,0xc)
IDS=(0x180b1010,0x180b101c,0x18002000,0x18002004)
GOOD_IDS=(0x10040101,0,0x8a00,0x8a00)
PRESERVED=(UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,
           UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11,
           UC_ARM_REG_R12,UC_ARM_REG_SP)
original_emi=bytes(range(256))*(EMI_SIZE//256)
cp_default={'midr':0x410fc073,'sctlr':0x00c5187f,'ctr':0x84448003,
            'ttbr0':0x41ffc059,'ttbr1':0,'ttbcr':0,'vbar':0x41f7d000,
            'par':0x12345000,'cntfrq':20000000,'mpidr':0x80000000}

def run(name,*,fast=True,expected_rc=0,cp=None,aon=None,pdma=0x1410,mask=0,
        ids=GOOD_IDS,address=BASE,sp=0x41e7b000,gd=0x41e7c000,
        caller=0x41f7f774,cpsr=0x600001d3,coarse=None,
        fault_page=None,fault_write=False,alias_page=None,alias_target=EMI,
        initial_complete=0,corrupt_source=None,ready_timeout=False,
        control_fail=None,restore_fail=None,release_fail=False,stop_fail=False,
        backup_fail=False,dest_crc_fail=False,backup_corrupt=False,
        restore_corrupt=False,late_dma=False,timer_stuck=False,
        timer_stalls_after_stop=False,timer_backwards_in_wait=False,
        uart_never=False,uart_after_release=False,controls_already_set=False):
    uc=Uc(UC_ARCH_ARM,UC_MODE_ARM)
    uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A7)
    uc.mem_map(0x40000000,0x2000000)
    uc.mem_write(address,payload)
    uc.mem_write(EMI,original_emi)
    if corrupt_source is not None: uc.mem_write(BASE+corrupt_source,b'\xff')
    image_before=bytes(uc.mem_read(address,0x50000))
    regs=dict(AON); regs.update(aon or {})
    old_controls=(0x20,0x200,0x7000)
    if controls_already_set: old_controls=tuple(v|m for v,m in zip(old_controls,MASKS))
    regs.update(dict(zip(CTRL,old_controls)))
    regs.update(dict(zip(IDS,ids)))
    regs[0x1b100a04]=pdma; regs[0x1b100a28]=mask
    cpvals=dict(cp_default); cpvals.update(cp or {})
    table=cpvals['ttbr0']&0xffffc000
    if 0x40200000<=table<=0x41ffc000 and not (BASE<=table<BASE+len(payload)):
        entries=[(i<<20)|0xc12 for i in range(4096)]
        if coarse is not None: entries[13]=(coarse&0xfffffc00)|1
        uc.mem_write(table,struct.pack('<4096I',*entries))
    uc.reg_write(UC_ARM_REG_CPSR,cpsr)
    saved={r:0x45000000+i*0x100 for i,r in enumerate(PRESERVED)}
    saved[UC_ARM_REG_SP]=sp; saved[UC_ARM_REG_R9]=gd
    for reg,value in saved.items(): uc.reg_write(reg,value)
    uc.reg_write(UC_ARM_REG_LR,caller)
    output=bytearray(); write_counts=Counter(); cache_counts=Counter()
    cp_counts=Counter(); transfers=[]; cpu_copy=[]; crc_calls=[]; mmio_reads=Counter()
    stage=0; released=False; release_seen=False; stopped=False; completion_reads=0
    current_par=cpvals['par']; counter=1_000_000_000; wait_counter_reads=0
    restore_crc_seen=0; uart_reads=0
    def finish(value):
        uc.reg_write(UC_ARM_REG_R0,value&0xffffffff)
        uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
    def mread(cpu,offset,size,page):
        nonlocal completion_reads,uart_reads
        a=page+offset; mmio_reads[a]+=1
        if a==UART+0x14:
            assert size==4; uart_reads+=1
            return 0 if uart_never or (uart_after_release and release_seen) else 0x20
        if a==COMPLETE:
            assert size==4
            if not released: return initial_complete
            completion_reads+=1
            if not ready_timeout and completion_reads>=3:
                uc.mem_write(EMI+0x1f0100,b'MCU writes outside the two loaded blob intervals')
                if backup_corrupt:
                    old=uc.mem_read(BACKUP+0x1234,1)[0]
                    uc.mem_write(BACKUP+0x1234,bytes([old^1]))
                return 0x1d1e
            return 0
        assert a in regs,('out-of-scope MMIO read',hex(a),size)
        assert size==(2 if a in IDS[2:] else 4),(hex(a),size)
        if a in CTRL and control_fail==CTRL.index(a) and stage==80:
            return regs[a]&~MASKS[CTRL.index(a)]
        return regs[a]&((1<<(size*8))-1)
    def mwrite(cpu,offset,size,value,page):
        nonlocal stage,released,release_seen,stopped
        a=page+offset
        assert size==4
        if a==UART:
            assert 0<=value<256; output.append(value)
            if value==10:
                line=bytes(output).splitlines()[-1]
                if line.startswith(b'STAGE='): stage=int(line[6:],16)
            return
        assert a in (*CTRL,RESET),('forbidden peripheral write',hex(a))
        write_counts[hex(a)]+=1
        if a==RESET:
            assert value&0xff000000==0x88000000,'reset key changed'
            want_release=not value&0x1000
            if want_release:
                assert all((regs[c]&m)==m for c,m in zip(CTRL,MASKS))
                assert bytes(uc.mem_read(EMI,72096))==payload[0x4000:0x4000+72096]
                assert bytes(uc.mem_read(EMI+0x43000,169240))==payload[0x18000:0x18000+169240]
                if release_fail: return
                released=True; release_seen=True
            elif release_seen:
                if stop_fail: return
                released=False; stopped=True
            regs[a]=value&0x00ffffff
        else:
            index=CTRL.index(a)
            if restore_fail==index and stage==140: return
            regs[a]=value
    pages={a&~0xfff for a in regs}|{UART,COMPLETE&~0xfff}
    for page in sorted(pages): uc.mmio_map(page,4096,mread,page,mwrite,page)
    def memwrite(cpu,access,a,size,value,unused):
        if sp-0x4000<=a and a+size<=sp: write_counts['stack']+=1; return
        if EMI<=a and a+size<=EMI+EMI_SIZE:
            assert regs[RESET]&0x1000,'CPU wrote EMI while MCU released'
            assert stage in (70,130),('unexpected EMI write stage',stage)
            if stage==70:
                assert a+size<=EMI+72096 or EMI+0x43000<=a and a+size<=EMI+0x43000+169240
            write_counts['EMI']+=1; return
        if BACKUP<=a and a+size<=BACKUP+EMI_SIZE:
            assert regs[RESET]&0x1000 and stage==60
            write_counts['backup']+=1; return
        assert a in (UART,RESET,*CTRL),('out-of-scope CPU RAM write',hex(a),size)
    uc.hook_add(UC_HOOK_MEM_WRITE,memwrite)
    def cp_hook(cpu,pc,size,unused):
        nonlocal current_par,counter,wait_counter_reads
        if pc in entry_reads:
            key,reg=entry_reads[pc]
            uc.reg_write(reg,current_par if key=='par' else cpvals[key]); cp_counts['entry_snapshot']+=1
        elif pc==symbols['midr_op']:
            uc.reg_write(UC_ARM_REG_R0,cpvals['midr']); cp_counts['midr']+=1
        elif pc in snapshot_ops:
            uc.reg_write(UC_ARM_REG_R1,cpvals[snapshot_ops[pc]]); cp_counts['snapshot']+=1
        elif pc==symbols['counter_op']:
            if timer_backwards_in_wait and stopped:
                wait_counter_reads+=1
                counter=1_000_000_000-wait_counter_reads*100
            elif not timer_stuck and not (timer_stalls_after_stop and stopped):
                counter+=20000
            uc.reg_write(UC_ARM_REG_R0,counter&0xffffffff)
            uc.reg_write(UC_ARM_REG_R1,counter>>32); cp_counts['counter']+=1
        elif pc in ats_ops:
            va=uc.reg_read(UC_ARM_REG_R0); write=ats_ops[pc]
            current_par=va&0xfffff000
            if fault_page is not None and va&~0xfff==fault_page and (write or not fault_write): current_par=1
            if alias_page is not None and va&~0xfff==alias_page: current_par=alias_target
            cp_counts['ats_write' if write else 'ats_read']+=1
        elif pc in par_reads:
            uc.reg_write(par_reads[pc],current_par); cp_counts['par_read']+=1
        elif pc in par_restores:
            current_par=uc.reg_read(par_restores[pc]); cp_counts['par_restore']+=1
        elif pc in (symbols['clean_op'],symbols['invalidate_op']):
            a=uc.reg_read(UC_ARM_REG_R0); line=uc.reg_read(UC_ARM_REG_R2)
            assert line in (32,64,128,256) and a%line==0
            assert EMI<=a<EMI+EMI_SIZE or BACKUP<=a<BACKUP+EMI_SIZE,hex(a)
            cache_counts['clean' if pc==symbols['clean_op'] else 'invalidate']+=1
        else: raise AssertionError(hex(pc))
        uc.reg_write(UC_ARM_REG_PC,pc+4)
    snapshot_ops={symbols['snapshot_'+name]:name for name in cp_default}
    entry_reads={symbols['entry_'+name+'_op']:(name,UC_ARM_REG_R0) for name in ('midr','sctlr','ttbcr')}
    entry_reads[symbols['entry_save_par_op']]=('par',UC_ARM_REG_R12)
    ats_ops={symbols[prefix+'translate_'+kind+'_op']:kind=='write' for prefix in ('','entry_') for kind in ('read','write')}
    par_reads={symbols['translate_par_op']:UC_ARM_REG_R0,
               symbols['entry_read_par_op']:UC_ARM_REG_R1,symbols['entry_write_par_op']:UC_ARM_REG_R1}
    par_restores={symbols['restore_par_op']:UC_ARM_REG_R0,
                  symbols['entry_restore_par_op']:UC_ARM_REG_R12,symbols['entry_fail_restore_par_op']:UC_ARM_REG_R12}
    opnames=['midr_op','counter_op','translate_read_op','translate_write_op',
             'translate_par_op','restore_par_op','clean_op','invalidate_op']
    for pc in set(snapshot_ops)|set(entry_reads)|set(ats_ops)|set(par_reads)|set(par_restores)|{symbols[n] for n in opnames}:
        uc.hook_add(UC_HOOK_CODE,cp_hook,begin=pc,end=pc)
    def fast_hook(cpu,pc,size,unused):
        nonlocal restore_crc_seen
        a,b,n=[uc.reg_read(r) for r in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2)]
        if pc==symbols['c80_crc32']:
            assert (EMI<=a and a+b<=EMI+EMI_SIZE or BASE<=a and a+b<=BASE+len(payload))
            v=zlib.crc32(bytes(uc.mem_read(a,b))); crc_calls.append([hex(a),b,stage])
            if backup_fail and a==BACKUP and stage==60: v^=1
            if dest_crc_fail and a==EMI and b==72096 and stage==70: v^=1
            if late_dma and a==EMI and b==EMI_SIZE and stage==130:
                restore_crc_seen+=1
                if restore_crc_seen==1: uc.mem_write(EMI+0x12,b'\xff')
            finish(v)
        else:
            assert pc==symbols['c80_copy']
            assert regs[RESET]&0x1000,'copy performed while MCU active'
            assert (a,b,n) in ((BACKUP,EMI,EMI_SIZE),(EMI,BASE+0x4000,72096),
                              (EMI+0x43000,BASE+0x18000,169240),(EMI,BACKUP,EMI_SIZE))
            cpu_copy.append([hex(a),hex(b),n,stage])
            uc.mem_write(a,bytes(uc.mem_read(b,n)))
            if restore_corrupt and a==EMI and b==BACKUP: uc.mem_write(EMI,b'\xff')
            # The pinned GCC body leaves r0/r1/r2 unchanged; its same-TU
            # callers use that interprocedural register knowledge.
            finish(a)
    if fast:
        for name_ in ('c80_crc32','c80_copy'):
            pc=symbols[name_]; uc.hook_add(UC_HOOK_CODE,fast_hook,begin=pc,end=pc)
    start_time=time.monotonic()
    uc.emu_start(address,caller,timeout=45_000_000,count=700_000_000)
    elapsed=time.monotonic()-start_time
    assert uc.reg_read(UC_ARM_REG_PC)==caller,(name,'did not return',hex(uc.reg_read(UC_ARM_REG_PC)),output[-1500:])
    rc=uc.reg_read(UC_ARM_REG_R0)
    text=output.decode('ascii')
    assert rc==expected_rc,(name,rc,expected_rc,text)
    for reg,value in saved.items(): assert uc.reg_read(reg)==value,(name,'callee register changed',reg)
    assert uc.reg_read(UC_ARM_REG_CPSR)&0x3ff==cpsr&0x3ff
    assert bytes(uc.mem_read(address,0x50000))==image_before,'source image changed'
    assert current_par==cpvals['par'],'PAR scratch not restored'
    fields={k:int(v,16) for k,v in re.findall(r'^([A-Z0-9_]+)=([0-9a-f]{8})\r?$',text,re.M)}
    actual_ddr=bytes(uc.mem_read(EMI,EMI_SIZE))
    if expected_rc not in (80,81,82,83): assert actual_ddr==original_emi,(name,'DDR not restored')
    if rc==0:
        assert fields['DDR_BACKUP_VALID']==fields['DDR_RESTORED']==fields['READY_OBSERVED']==1
        assert fields['CLEANUP_ERRORS']==fields['AON_CHANGED_BITS']==fields['CRITICAL_STOP']==0
        assert fields['DDR_ORIGINAL_CRC']==fields['DDR_BACKUP_CRC']==fields['DDR_RESTORED_CRC']==fields['DDR_RESTORED_CRC2']==zlib.crc32(original_emi)
        assert fields['MCU_STOPPED']==fields['POWER_CYCLE_REQUIRED']==1
        assert text.endswith('DONE\r\n') and stopped
    if expected_rc not in (48,80,81,82,83):
        assert all(regs[a]==old for a,old in zip(CTRL,old_controls)),(name,'control not restored')
    if expected_rc not in (80,9): assert regs[RESET]&0x1000
    if uart_never: assert uart_reads==1_000_000 and not cp_counts['snapshot'] and not write_counts['EMI']
    result={'name':name,'passed':True,'rc':rc,'seconds':round(elapsed,3),
            'real_crc_and_copy_executed':not fast,'cp15_and_mcu_modeled':True,
            'ready_observed':bool(fields.get('READY_OBSERVED',0)),
            'DDR_matches_original':actual_ddr==original_emi,'release_seen':release_seen,'reset_held_at_exit':bool(regs[RESET]&0x1000),
            'cache_instruction_sites_intercepted_in_actual_ARM_loops':dict(cache_counts),
            'cp15_instruction_model_counts':dict(cp_counts),'cpu_write_counts':dict(write_counts),
            'host_substituted_crc_calls':crc_calls,'host_substituted_copy_calls':cpu_copy,
            'all_callee_registers_r12_sp_control_bits_preserved':True}
    return result,text

cases=[]
def test(name,**kwargs):
    result,text=run(name,**kwargs); cases.append(result)
    if len(cases)%10==0 or not kwargs.get('fast',True):
        print(f'PASS {name} ({result["seconds"]}s); completed {len(cases)} cases',flush=True)
    return text

if not options.fast_only:
    example=test('full-ARM-CRC-copy-cache-ATS-and-MCU-stop-restore',fast=False)
    (root/'example-emulated-output.txt').write_text(example)
if not options.full_only:
    test('fast-fault-harness-baseline')
    test('wrong-position',address=0x41100000,expected_rc=2)
    test('wrong-cpsr',cpsr=0x600000d3,expected_rc=3)
    test('wrong-cpu',cp={'midr':0x410fc075},expected_rc=3)
    test('wrong-gd',gd=EMI,expected_rc=4)
    test('wrong-stack',sp=0x41040000,expected_rc=4)
    test('stack-physical-alias-refused-before-push',alias_page=0x41e77000,alias_target=EMI,expected_rc=7)
    test('stack-write-permission-refused-before-push',fault_page=0x41e77000,fault_write=True,expected_rc=7)
    test('wrong-caller',caller=0x41003000,expected_rc=4)
    test('bad-cache-line',cp={'ctr':0x84408003},expected_rc=5)
    test('wrong-mpidr',cp={'mpidr':0x80000001},expected_rc=5)
    test('wrong-counter-frequency',cp={'cntfrq':0},expected_rc=5)
    test('LPAE-refused-without-PAR-write',cp={'ttbcr':0x80000000},expected_rc=6)
    test('TTBR-split-refused',cp={'ttbcr':1},expected_rc=6)
    test('different-SCTLR',cp={'sctlr':0x00c5187e},expected_rc=6)
    test('L1-table-in-EMI',cp={'ttbr0':EMI},expected_rc=6)
    test('L1-table-in-image',cp={'ttbr0':BASE},expected_rc=6)
    test('coarse-L2-table-in-EMI',coarse=EMI+0x1000,expected_rc=6)
    test('coarse-L2-table-in-backup',coarse=BACKUP,expected_rc=6)
    test('vector-aliases-EMI',alias_page=0x41f7d000,alias_target=EMI,expected_rc=6)
    test('vector-translation-fault',fault_page=0x41f7d000,expected_rc=6)
    test('L1-table-translation-fault',fault_page=0x41ffc000,expected_rc=6)
    test('EMI-write-permission-fault',fault_page=EMI,fault_write=True,expected_rc=7)
    test('backup-not-identity',alias_page=BACKUP,alias_target=0x41800000,expected_rc=7)
    test('upper-Uboot-RAM-not-identity',alias_page=0x41c01000,alias_target=EMI,expected_rc=7)
    test('stuck-counter-before-mutation',timer_stuck=True,expected_rc=8)
    test('PDMA-running',pdma=0x1455,expected_rc=9)
    test('PDMA-mask-on',mask=0x10001,expected_rc=9)
    for reg,value in ((0x10000220,0x100),(0x10000228,0xe0800122),(0x10000230,1),
                      (0x10000238,0xffffff21),(0x10000370,0x11050),(0x10006000,0),
                      (0x10006608,0),(0x1000660c,0),(RESET,0x8000),(RESET,0x9200)):
        test(f'bad-AON-{reg:08x}-{value:08x}',aon={reg:value},expected_rc=9)
    for index in range(4):
        bad=list(GOOD_IDS); bad[index]^=1
        test(f'bad-CONNSYS-ID-{index}',ids=bad,expected_rc=10)
    test('stale-ready-word',initial_complete=0x1d1e,expected_rc=11)
    test('bad-MCU-blob',corrupt_source=0x4000,expected_rc=20)
    test('bad-WIFI-blob',corrupt_source=0x18000,expected_rc=20)
    test('bad-backup-before-EMI-write',backup_fail=True,expected_rc=21)
    test('bad-copied-firmware-restores-DDR',dest_crc_fail=True,expected_rc=22)
    for index in range(3): test(f'control-readback-fail-{index}',control_fail=index,expected_rc=30)
    test('MCU-release-readback-fail',release_fail=True,expected_rc=31)
    test('MCU-ready-timeout-stops-and-restores',ready_timeout=True,expected_rc=32)
    for index in range(3): test(f'control-restore-fail-{index}',restore_fail=index,expected_rc=48)
    test('MCU-stop-failure-forbids-DDR-restore',stop_fail=True,expected_rc=80)
    test('counter-backwards-forbids-DDR-restore',timer_backwards_in_wait=True,expected_rc=81)
    test('counter-stalls-after-stop-forbids-DDR-restore',timer_stalls_after_stop=True,expected_rc=81)
    test('corrupt-backup-forbids-DDR-restore',backup_corrupt=True,expected_rc=82)
    test('restore-CRC-failure',restore_corrupt=True,expected_rc=83)
    test('late-DDR-write-detected',late_dma=True,expected_rc=83)
    test('already-set-owned-control-bits-preserved',controls_already_set=True)
    test('UART-dead-before-guards',uart_never=True,expected_rc=40)
    test('UART-dead-after-release-stops-and-restores',uart_after_release=True,expected_rc=40)

report={'scope':__doc__,'passed':True,'payload_bytes':len(payload),
        'payload_sha256':hashlib.sha256(payload).hexdigest(),'cases':cases,
        'full_actual_CRC_copy_cases':sum(c['real_crc_and_copy_executed'] for c in cases),
        'model_does_not_execute_vendor_MCU_firmware':True,
        'real_hardware_MCU_bootstrap_tested':False}
name='verification-full.json' if options.full_only else 'verification-fast.json' if options.fast_only else 'verification.json'
(root/name).write_text(json.dumps(report,indent=2)+'\n')
print(f'PASS: {len(cases)} ARM cases; full CRC/copy cases={report["full_actual_CRC_copy_cases"]}.',flush=True)
