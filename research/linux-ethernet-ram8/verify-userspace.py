#!/usr/bin/env python3
"""Execute actual ARM PID1 with a five-interface syscall model; verify IPv4 migration, failures and fd cleanup. Not a kernel/network hardware emulator."""
from pathlib import Path
import hashlib,json,struct
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_INTR
from unicorn.arm_const import *
ROOT=Path(__file__).resolve().parent
ELF=(ROOT/'build/userspace/init').read_bytes()
h=struct.unpack_from('<16sHHIIIIIHHHHHH',ELF)
assert ELF[:7]==b'\x7fELF\x01\x01\x01' and h[1:3]==(2,40)
entry,phoff,phsize,phcount=h[4],h[5],h[9],h[10]
segments=[struct.unpack_from('<8I',ELF,phoff+n*phsize) for n in range(phcount)]
assert all(s[0]!=3 for s in segments)
NAMES=['lan1','lan2','lan3','lan4','wan']
ENDPOINT=b'\xc0\xa8\x00\x01';MASK=b'\xff\xff\xff\x00'

def run_case(name,commands,*,initial=None,fault_at=0,after=False,mode=None,expected=None,proc_error=False,dsa_error=False,switch_error=False):
    cpu=Uc(UC_ARCH_ARM,UC_MODE_ARM);cpu.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A7)
    pages=set()
    for kind,off,addr,phys,filesz,memsz,flags,align in segments:
        if kind==1:pages.update(range(addr&~4095,(addr+memsz+4095)&~4095,4096))
    for page in pages:cpu.mem_map(page,4096)
    for kind,off,addr,phys,filesz,memsz,flags,align in segments:
        if kind==1:cpu.mem_write(addr,ELF[off:off+filesz])
    cpu.mem_map(0x70000000,65536);cpu.mem_write(0x70000000,b'\x5a'*4096)
    cpu.reg_write(UC_ARM_REG_CPSR,0x10);cpu.reg_write(UC_ARM_REG_SP,0x70010000)
    incoming=bytearray(commands.encode());output=bytearray();opened={};next_fd=3
    state={p:{'flags':0x1002,'ip':None,'mask':None} for p in NAMES}
    if initial=='lan1':state['lan1'].update(flags=0x1003,ip=ENDPOINT,mask=MASK)
    if initial=='stale':
        for i,p in enumerate(NAMES):state[p].update(flags=0x1003,ip=bytes([203,0,113,251+i]),mask=MASK)
    fake={'/proc/version':b'Linux test version\n','/proc/cpuinfo':b'ARM test CPU\n','/proc/meminfo':b'MemTotal:28000 kB\n','/proc/interrupts':b'20:7 c80-ram-pdma\n',
          '/proc/net/dev':b'eth0:120 2\nlan1:120 2\n','/proc/net/arp':b'192.168.0.3 neighbour\n','/sys/class/net/eth0/device/ram_state':b'pdma=00001455\n','/sys/class/net/eth0/carrier':b'1\n',
          '/sys/class/net/eth0/device/switch_state':b'C80 Linux MDIO snapshot v1\nresult=0 cleanup_errors=00000000 tainted=0\n'}
    if not dsa_error:fake.update({'/sys/class/net/eth0/dsa/tagging':b'rtl8_4\n','/sys/class/net/eth0/mtu':b'1508\n'})
    if switch_error:fake.pop('/sys/class/net/eth0/device/switch_state')
    mounts=[];numbers=set();trace=[];mutations=[];ioctls=0;switch_opens=0;paths=[]
    stdin_intr=stdout_intr=socket_intr=ioctl_intr=False;fault_hit=False
    def string(addr):
        b=bytearray()
        for i in range(256):
            c=cpu.mem_read(addr+i,1)[0]
            if not c:return b.decode()
            b.append(c)
        raise AssertionError('Unterminated user string')
    def snapshot():return {p:{k:(v.hex() if isinstance(v,bytes) else v) for k,v in s.items()} for p,s in state.items()}
    def syscall(uc,intr,data):
        nonlocal next_fd,stdin_intr,stdout_intr,socket_intr,ioctl_intr,ioctls,switch_opens,fault_hit
        assert intr==2
        nr=uc.reg_read(UC_ARM_REG_R7);numbers.add(nr)
        a,b,c,d,e=[uc.reg_read(reg) for reg in [UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R4]];rc=0
        if nr==281:
            assert(a,b,c)==(2,2,0)
            if mode=='socket-fail':rc=-97
            elif not socket_intr:socket_intr=True;rc=-4
            else:rc=next_fd;next_fd+=1;opened[rc]=['socket',0]
        elif nr==54:
            assert opened[a][0]=='socket'
            req=bytes(uc.mem_read(c,32));p=req[:16].split(b'\0')[0].decode();assert p in NAMES
            assert req[:16]==p.encode()+bytes(16-len(p))
            if not ioctl_intr:ioctl_intr=True;rc=-4
            else:
                ioctls+=1;fail=ioctls==fault_at;fault_hit|=fail;trace.append((p,b))
                if mode=='missing-interface' and p=='lan3':rc=-19
                elif fail and not after:rc=-5
                else:
                    s=state[p]
                    if b==0x8913:uc.mem_write(c+16,struct.pack('<H',s['flags']))
                    elif b==0x8914:
                        flags=struct.unpack_from('<H',req,16)[0]
                        if flags&1:
                            assert s['ip']==ENDPOINT and s['mask']==MASK
                            assert all(not(state[q]['flags']&1) and state[q]['ip'] is None for q in NAMES if q!=p)
                        s['flags']=flags;mutations.append((p,'flags',flags))
                    elif b==0x8915:
                        if mode=='address-read-fail':rc=-5
                        elif s['ip'] is None:rc=-99
                        else:uc.mem_write(c+16,b'\x02\x00\x00\x00'+s['ip']+bytes(8))
                    elif b==0x8916:
                        assert req[16:20]==b'\x02\x00\x00\x00';ip=req[20:24]
                        if ip==bytes(4):
                            if mode!='ignore-removal':s['ip']=None;s['mask']=None
                        else:
                            assert ip==ENDPOINT
                            assert all(state[q]['ip'] is None and not(state[q]['flags']&1) for q in NAMES if q!=p)
                            s['ip']=ip
                        mutations.append((p,'ip',ip.hex()))
                    elif b==0x891c:
                        assert req[16:20]==b'\x02\x00\x00\x00' and req[20:24]==MASK
                        s['mask']=MASK;mutations.append((p,'mask',MASK.hex()))
                    else:raise AssertionError(('Unknown ioctl',hex(b)))
                    if fail:rc=-5
        elif nr==5:
            path=string(a);paths.append(path)
            assert b==(2 if path=='/dev/console' else 0),'All sysfs/MTD opens must be read-only in this command suite'
            if path.endswith('/switch_state'):switch_opens+=1
            if path.startswith('/sys/class/net/'):
                parts=path.split('/')
                if len(parts)==6 and parts[4] in NAMES and parts[5] in ['carrier','mtu'] and not dsa_error:
                    p=parts[4];fake[path]=(b'1\n' if state[p]['flags']&1 else b'') if parts[5]=='carrier' else b'1500\n'
            if path!='/dev/console' and(path not in fake or proc_error):rc=-2
            else:rc=next_fd;next_fd+=1;opened[rc]=[path,0]
        elif nr==63:assert a in opened and b in [0,1,2];rc=b
        elif nr==21:
            fs=string(c);mounts.append(fs);rc=-1 if fs=='proc' and proc_error else 0
        elif nr==4:
            assert a==1,'No sysfs action writes in RAM8 commands'
            if not stdout_intr:stdout_intr=True;rc=-4
            else:rc=min(c,7);output.extend(uc.mem_read(b,rc))
        elif nr==3:
            if a==0:
                if not stdin_intr:stdin_intr=True;rc=-4
                elif not incoming:uc.emu_stop()
                else:assert c==1;uc.mem_write(b,bytes(incoming[:1]));del incoming[:1];rc=1
            else:
                path,pos=opened[a];chunk=fake[path][pos:pos+min(c,13)]
                if chunk:uc.mem_write(b,chunk)
                opened[a][1]+=len(chunk);rc=len(chunk)
        elif nr==6:assert a in opened;del opened[a]
        else:raise AssertionError(('Unexpected syscall',nr))
        uc.reg_write(UC_ARM_REG_R0,rc&0xffffffff)
    cpu.hook_add(UC_HOOK_INTR,syscall);cpu.emu_start(entry,0,count=10_000_000)
    out=output.decode();assert not incoming and out.endswith('c80-linux> ')
    assert 'C80 Linux RAM userspace ready.' in out
    assert not opened,'Leaked fds'
    assert mounts==['devtmpfs','proc','sysfs'] and bytes(cpu.mem_read(0x70000000,4096))==b'\x5a'*4096
    if fault_at:assert fault_hit
    if expected in NAMES:
        assert state[expected]['flags']&1 and state[expected]['ip']==ENDPOINT and state[expected]['mask']==MASK
        assert all(not(state[p]['flags']&1) and state[p]['ip'] is None for p in NAMES if p!=expected)
        assert expected+' configured: 192.168.0.1/24, interface up.' in out
    if expected=='down':assert all(not(s['flags']&1) and s['ip'] is None for s in state.values())
    if expected=='unchanged-lan1':assert state['lan1']['flags']&1 and state['lan1']['ip']==ENDPOINT and not mutations
    if expected=='failed':
        assert 'Port configuration stopped; inspect ports.' in out
        assert ' configured: ' not in out
        # No successful opening of a new management endpoint after an error.
        assert not(state['lan2']['flags']&1) and state['lan2']['ip'] is None
    if mode=='ignore-removal':assert 'IPv4 removal not confirmed' in out and expected=='failed'
    if name=='invalid-port-names':assert not trace and out.count('Usage: port ')==8
    if name=='ports-with-stale-addresses':
        assert not mutations
        for i in range(5):assert '203.0.113.'+str(251+i) in out
    if name=='dsa-selected-wan':assert '/sys/class/net/wan/carrier' in paths and '/sys/class/net/lan1/carrier' not in paths
    if name=='dsa-missing':assert out.count('Cannot open requested file.')==4
    if name=='switch-readonly':assert switch_opens==2 and out.count('C80 Linux MDIO snapshot v1')==2
    if switch_error:assert switch_opens==1 and 'Cannot open requested file.' in out
    if proc_error:assert 'procfs mount failed.' in out and 'Cannot open requested file.' in out
    if name=='basic-commands':
        assert all(fake[p].decode() in out for p in ['/proc/version','/proc/cpuinfo','/proc/meminfo','/proc/interrupts']) and 'Unknown command' in out
    if name=='overlong-command':assert 'Unknown command' in out and 'Usage: port ' in out
    return {'name':name,'status':'pass','syscalls':sorted(numbers),'ioctls':ioctls,'mutations':len(mutations),'stdout_bytes':len(output)},trace,state

cases=[]
def add(*args,**kwargs):
    r,trace,state=run_case(*args,**kwargs);cases.append(r);return trace,state
add('basic-commands','help\nversion\ncpu\nmem\nirq\nunknown\ncpulink\n')
add('overlong-command','a'*100+'\nport\n')
add('procfs-failure','mem\n',proc_error=True)
add('netup-down','netup\nports\nnet\nnetdown\nports\n',expected='down')
add('network-socket-failure','netup\n',mode='socket-fail')
add('preflight-missing-interface','port lan2\n',initial='lan1',mode='missing-interface',expected='unchanged-lan1')
for p in NAMES:add('select-'+p,'port '+p+'\nports\ndsa\n',initial='lan1',expected=p)
trace,_=add('normal-migration-oracle','port lan2\n',initial='lan1',expected='lan2')
add('all-five-port-migrations','netup\n'+''.join('port '+p+'\nports\ndsa\n' for p in NAMES[1:])+ 'netdown\nnetup\nport lan1\nports\n',expected='lan1')
add('repeat-same-port','port wan\nport wan\nnetdown\nnetup\nports\n',expected='wan')
add('invalid-port-names','port\nport eth0\nport LAN2\nport lan9\nport lan2 extra\nport  lan2\nport ../wan\nport wan/\n')
add('ports-with-stale-addresses','ports\n',initial='stale')
add('cleanup-all-stale-addresses','port lan4\nports\n',initial='stale',expected='lan4')
add('ignored-removal-refused','port lan2\nports\n',initial='lan1',mode='ignore-removal',expected='failed')
add('address-read-error','port lan2\n',initial='lan1',mode='address-read-fail',expected='failed')
add('dsa-selected-wan','port wan\ndsa\n',expected='wan')
add('dsa-missing','dsa\n',dsa_error=True)
add('switch-readonly','switch\nswitch\n')
add('switch-missing','switch\n',switch_error=True)
# Every transaction in a successful old-LAN1 -> LAN2 migration, before/after
# any effect. A one-shot failure must be reported and all descriptors closed.
for at in range(1,len(trace)+1):
    for after in [False,True]:add('migration-fault-'+str(at)+('-after' if after else '-before'),'port lan2\nports\n',initial='lan1',fault_at=at,after=after,expected='failed')
result={'scope':__doc__,'status':'pass','init_bytes':len(ELF),'init_sha256':hashlib.sha256(ELF).hexdigest(),'cases':cases,'fault_injection_cases':2*len(trace),'normal_migration_ioctls':len(trace),'hardware_tested_ram8':False,'invariants':['Fixed allowlist, no conduit address/flags mutations','Every old primary IPv4 removed and read back absent before new address','At successful up only selected interface owns management IPv4 and is admin up','Preflight missing-interface failure makes no mutations','Target bring-up failure triggers down/address cleanup','Unknown names and path-like strings perform no ioctls','EINTR/short I/O, read-only sysfs, fd/stack cleanup','Actual ARM ELF executed; not a Linux or Ethernet emulation']}
(ROOT/'artifacts/userspace-verification.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'status':'pass','cases':len(cases),'fault_injection_cases':result['fault_injection_cases'],'normal_migration_ioctls':len(trace),'init_sha256':result['init_sha256']},indent=2))
