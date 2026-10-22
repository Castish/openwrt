#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the same ARM clock/sleep diagnostic on original RAM40 and current RAM42 QEMU.
Uses real Linux syscalls and generic timer interrupts; no MCU, DMA or RF model.
"""
from pathlib import Path
import argparse,hashlib,json,os,re,subprocess

R=Path(__file__).resolve().parent
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--parent',action='store_true')
args=parser.parse_args()
boot=R.parent/'openwrt-ram40-rx-status' if args.parent else R
mode='timer-parent' if args.parent else 'timer-hires'
source=(R.parent/'openwrt-ram31-scheduler/verify-qemu-network.py').read_text().split('\ntry:\n')[0]
source=source.replace("mode='linux-network'",f'mode={mode!r}')
source=source.replace('base = Path(__file__).resolve().parent',f'base = Path({str(R)!r})')
source=source.replace("str(base / 'run-qemu-emi-check.sh')",repr(str(boot/'run-qemu-auth.sh')))
n={'__file__':str(__file__),'__name__':mode}
exec(compile(source,str(__file__),'exec'),n)
ssh=None;checks=[]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def check(name,condition):
    assert condition,name
    checks.append(name);print('PASS QEMU TIMER '+mode+' '+name,flush=True)
def remote(command,data=None):
    result=subprocess.run(ssh+[command],input=data,capture_output=True,timeout=25)
    assert result.returncode==0,(command,result.returncode,result.stdout,result.stderr)
    return result.stdout
try:
    n['receive_until'](b'Please press Enter to activate this console.',timeout=60)
    n['send']('');n['receive_until'](n['prompt']);n['send']('');n['receive_until'](n['prompt'])
    n['command']('network','ubus -t 45 wait_for network')
    n['command']('management','ifconfig eth0 192.168.0.1 netmask 255.255.255.0 up')
    keys=json.loads((R.parent/'ssh-identity-v1/ssh-host-public.json').read_text())['host_keys']
    known=R/'private'/('qemu-'+mode+'-known-hosts')
    known.write_text(''.join('[127.0.0.1]:40223 '+x['public_key']+'\n' for x in keys))
    ask=R/'private'/('qemu-'+mode+'-askpass.sh')
    ask.write_text("#!/bin/sh\nprintf '%s\\n' openwrt\n");ask.chmod(0o700)
    env=dict(os.environ,SSH_ASKPASS=str(ask),SSH_ASKPASS_REQUIRE='force',DISPLAY=':c80-timer')
    socket=R/'private'/('timer-p' if args.parent else 'timer-h');socket.unlink(missing_ok=True)
    options=['ssh','-F','/dev/null','-p','40223','-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no',
             '-o','UserKnownHostsFile='+str(known),'-o','PreferredAuthentications=password','-o','PubkeyAuthentication=no',
             '-o','NumberOfPasswordPrompts=1','-o','HostKeyAlgorithms=ssh-ed25519']
    master=subprocess.run(options+['-M','-S',str(socket),'-fN','root@127.0.0.1'],env=env,
                          stdin=subprocess.DEVNULL,capture_output=True,start_new_session=True,timeout=20)
    assert master.returncode==0,master.stderr
    ssh=options+['-S',str(socket),'root@127.0.0.1']
    release=remote('uname -r').decode().strip()
    expected='6.12.113-c80-openwrt-ram40-qemu-check' if args.parent else '6.12.113-c80-openwrt-ram42-qemu-check'
    check('real-booted-kernel-release',release==expected)
    binary=(R/'rootfs/usr/sbin/c80-timer-check').read_bytes()
    program='/tmp/c80-timer-check' if args.parent else '/usr/sbin/c80-timer-check'
    if args.parent:
        remote('cat > '+program,binary);remote('chmod 700 '+program)
    check('same-exact-ARM-diagnostic',remote('cat '+program)==binary)
    output=remote(program).decode().strip()
    assert output.startswith('C80 timers v1 '),output
    stats={key:int(value) for key,value in re.findall(r'([a-z0-9_]+)=(\d+)',output)}
    resolution=10000000 if args.parent else 1
    check('actual-monotonic-timer-resolution',stats['monotonic_res_ns']==resolution)
    check('actual-realtime-timer-resolution',stats['realtime_res_ns']==resolution)
    check('64-real-nanosleeps-return-after-requested-interval',stats['samples']==64 and
          stats['requested_sleep_ns']==1000000 and stats['min_ns']>=1000000 and
          stats['min_ns']<=stats['mean_ns']<=stats['max_ns'] and stats['peripheral_access']==0)
    result={'passed':True,'cases_passed':len(checks),'cases':checks,'kernel':release,
            'same_diagnostic_binary_sha256':hashlib.sha256(binary).hexdigest(),
            'diagnostic_source_sha256':sha(R/'c80_timer_check.c'),
            'verification_source_sha256':sha(Path(__file__)),
            'QEMU_kernel_sha256':sha(boot/'build-qemu/arch/arm/boot/zImage'),
            'statistics':stats,'real_Linux_syscalls_and_generic_timer':True,
            'physical_MT7626_clockevents_or_RF_emulated':False,
            'parent_issued_kernel_unmodified':args.parent,'latency_distribution_is_not_WiFi_RTT':True}
    (R/'evidence'/('qemu-'+mode+'-result.json')).write_text(json.dumps(result,indent=2)+'\n')
    print(output,flush=True)
finally:
    if ssh:
        subprocess.run(ssh[:-1]+['-O','exit','root@127.0.0.1'],capture_output=True,timeout=5)
    if n['process'].poll() is None:
        n['process'].terminate();n['process'].wait(timeout=5)
    n['rawlog'].close()
