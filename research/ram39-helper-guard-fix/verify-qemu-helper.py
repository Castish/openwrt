#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Boot unchanged RAM39 QEMU kernel plus the exact corrected external CPIO.
Exercise the actual installed shell helper's version guard, with an existing
once-directory stopping positive cases before hardware preparation.
"""
from pathlib import Path
import hashlib,json,os,re,subprocess
R=Path(__file__).resolve().parent;P=R.parent/'openwrt-ram39-gtk-init'
s=(R.parent/'openwrt-ram31-scheduler/verify-qemu-network.py').read_text().split('\ntry:\n')[0]
s=s.replace("mode='linux-network'","mode='helper-guard'").replace('base = Path(__file__).resolve().parent',f'base = Path({str(R)!r})').replace("str(base / 'run-qemu-emi-check.sh')",f'{str(R/"run-qemu-auth.sh")!r}')
n={'__file__':str(__file__),'__name__':'helper_guard_harness'};exec(compile(s,str(__file__),'exec'),n)
checks=[];ssh=None
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def check(name,okay):
 assert okay,name
 checks.append(name);print('PASS HELPER '+name,flush=True)
def remote(cmd,data=None,okay=True):
 q=subprocess.run(ssh+[cmd],input=data,capture_output=True,timeout=20)
 if okay:assert q.returncode==0,(cmd,q.returncode,q.stdout,q.stderr)
 return q
def uname_fixture(version):
 assert re.fullmatch(r'[a-zA-Z0-9_.-]+',version)
 remote('cat > /tmp/c80-guard-bin/uname',("#!/bin/sh\nprintf '%s\\n' '"+version+"'\n").encode())
 remote('chmod 700 /tmp/c80-guard-bin/uname')
try:
 n['receive_until'](b'Please press Enter to activate this console.',timeout=60)
 n['send']('');n['receive_until'](n['prompt']);n['send']('');n['receive_until'](n['prompt'])
 n['command']('network','ubus -t 45 wait_for network')
 n['command']('management','ifconfig eth0 192.168.0.1 netmask 255.255.255.0 up')
 keys=json.loads((R.parent/'ssh-identity-v1/ssh-host-public.json').read_text())['host_keys']
 known=R/'private/qemu-known-hosts';known.write_text(''.join('[127.0.0.1]:40223 '+k['public_key']+'\n' for k in keys))
 ask=R/'private/askpass.sh';ask.write_text("#!/bin/sh\nprintf '%s\\n' openwrt\n");ask.chmod(0o700)
 env=dict(os.environ,SSH_ASKPASS=str(ask),SSH_ASKPASS_REQUIRE='force',DISPLAY=':c80-guard')
 socket=R/'private/qemu-ssh-socket';socket.unlink(missing_ok=True)
 options=['ssh','-F','/dev/null','-p','40223','-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no','-o','UserKnownHostsFile='+str(known),'-o','PreferredAuthentications=password','-o','PubkeyAuthentication=no','-o','NumberOfPasswordPrompts=1','-o','HostKeyAlgorithms=ssh-ed25519']
 master=subprocess.run(options+['-M','-S',str(socket),'-fN','root@127.0.0.1'],env=env,stdin=subprocess.DEVNULL,capture_output=True,start_new_session=True,timeout=20)
 assert master.returncode==0,master.stderr
 ssh=options+['-S',str(socket),'root@127.0.0.1']
 check('same-pinned-SSH-identity-and-root-password',remote('id -u').stdout.strip()==b'0')
 check('external-overlay-marker',remote('cat /etc/c80-helper-fix').stdout==b'ram39-helper-fix1\n')
 check('corrected-helper-replaced-built-in-faulty-helper',remote('cat /usr/sbin/c80-wifi').stdout==(R/'c80-wifi').read_bytes())
 details=remote('test -x /usr/sbin/c80-wifi && ls -ln /usr/sbin/c80-wifi').stdout.split()
 check('helper-root-owned-executable',details[0]==b'-rwxr-xr-x' and details[2:4]==[b'0',b'0'])
 spec=__import__('importlib.util',fromlist=['util']);sp=spec.spec_from_file_location('cpio_reader',P/'cpio_tools.py');cp=spec.module_from_spec(sp);sp.loader.exec_module(cp)
 auth=cp.entries((P/'c80-auth.cpio').read_bytes())
 for path,item in auth.items():
  if path.startswith('etc/dropbear/dropbear_') or path=='etc/shadow':
   digest=hashlib.sha256(item[5]).hexdigest()
   check('preserved-'+Path(path).name,remote('sha256sum /'+path).stdout.decode().split()[0]==digest)
 q=remote('c80-wifi start',okay=False)
 check('real-QEMU-kernel-rejected-before-preparation',q.returncode!=0 and b'Requires the RAM39' in q.stdout)
 check('wrong-version-created-no-once-directory',remote('test ! -e /tmp/c80-wifi-once').returncode==0)
 remote('mkdir /tmp/c80-wifi-once /tmp/c80-guard-bin')
 release=json.loads((R/'PROVENANCE.json').read_text())['kernel_release'];uname_fixture(release)
 q=remote('PATH=/tmp/c80-guard-bin:$PATH c80-wifi start',okay=False)
 check('actual-helper-accepts-exact-physical-RAM39-release',q.returncode!=0 and b'Already prepared this boot' in q.stdout and b'Requires' not in q.stdout)
 remote('cat > /tmp/c80-helper-before',(P/'rootfs/usr/sbin/c80-wifi').read_bytes())
 q=remote('PATH=/tmp/c80-guard-bin:$PATH sh /tmp/c80-helper-before start',okay=False)
 check('old-issued-helper-reproduces-owner-version-refusal',q.returncode!=0 and b'Requires the RAM39' in q.stdout and b'Already prepared' not in q.stdout)
 uname_fixture('6.12.113-c80-openwrt-ram39-bmc-profile')
 q=remote('PATH=/tmp/c80-guard-bin:$PATH c80-wifi start',okay=False)
 check('corrected-helper-rejects-stale-bmc-profile-name',q.returncode!=0 and b'Requires the RAM39' in q.stdout)
 check('positive-probe-stopped-before-MCU-worker-or-service-start',remote('test ! -e /tmp/c80-wifi-once/pid').returncode==0)
 check('real-initramfs-unpacking-succeeded',b'Unpacking initramfs' in n['all_output'] and b'Initramfs unpacking failed' not in n['all_output'])
 report={'passed':True,'cases_passed':len(checks),'cases':checks,'actual_installed_helper_guard_executed':True,'version_fixture_from_exact_physical_kernel':True,'positive_case_deliberately_stopped_at_existing_once_directory':True,'real_AP_start_or_radio_not_exercised':True,'old_issued_helper_refusal_reproduced':True,'personal_auth_preserved':True,'external_CPIO_sha256':sha(R/'c80-auth-helper-fix1.cpio'),'QEMU_kernel_sha256':sha(P/'build-qemu/arch/arm/boot/zImage'),'helper_sha256':sha(R/'c80-wifi'),'verification_source_sha256':sha(Path(__file__))}
 (R/'evidence/qemu-helper-result.json').write_text(json.dumps(report,indent=2)+'\n')
 print('PASS: '+str(len(checks))+' actual-QEMU external-overlay/SSH/helper-guard checks; no AP/MCU/RF test.',flush=True)
finally:
 if ssh:subprocess.run(ssh[:-1]+['-O','exit','root@127.0.0.1'],capture_output=True,timeout=5)
 if n['process'].poll() is None:n['process'].terminate();n['process'].wait(timeout=5)
 n['rawlog'].close()
