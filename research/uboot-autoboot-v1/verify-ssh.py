#!/usr/bin/env python3
"""Actual unchanged RAM31 OpenWrt/Dropbear SSH login in QEMU, no C80 hardware."""
from pathlib import Path
import hashlib,json,subprocess
R=Path(__file__).resolve().parent
P=R.parent/'openwrt-ram31-scheduler'
# Reuse the already tested paced-UART harness, without its test body or writes
# into the frozen parent's evidence directory.
s=(P/'verify-qemu-network.py').read_text().split('\ntry:\n')[0]
s=s.replace("mode='linux-network'","mode='autoboot-ssh'")
s=s.replace('base = Path(__file__).resolve().parent',f'base = Path({str(P)!r})')
s=s.replace("evidence = base / 'evidence'",f"evidence = Path({str(R/'evidence')!r})")
s=s.replace("str(base / 'run-qemu-emi-check.sh')",f"{str(R/'run-qemu-ssh.sh')!r}")
ns={'__file__':str(__file__),'__name__':'qemu_ssh_harness'}
exec(compile(s,str(__file__),'exec'),ns)
try:
 ns['receive_until'](b'Please press Enter to activate this console.',timeout=60)
 ns['send']('');ns['receive_until'](ns['prompt']);ns['send']('');ns['receive_until'](ns['prompt'])
 ns['command']('network-ready','ubus -t 45 wait_for network')
 ns['command']('virtual-management-LAN','ifconfig eth0 192.168.0.1 netmask 255.255.255.0 up')
 ns['command']('dropbear-running',"ubus call service list '{\"name\":\"dropbear\"}'",'"running": true')
 cmd=['ssh','-F','/dev/null','-p','40222','-o','BatchMode=yes','-o','ConnectTimeout=8',
      '-o','PreferredAuthentications=none','-o','NumberOfPasswordPrompts=0',
      '-o','StrictHostKeyChecking=accept-new','-o',f'UserKnownHostsFile={R}/evidence/qemu-ssh-known-hosts',
      'root@127.0.0.1',"printf 'C80_SSH_READY\\n'; uname -r; id -u"]
 result=subprocess.run(cmd,capture_output=True,text=True,timeout=20)
 report={'scope':__doc__,'QEMU_services_ready':True,'none_authentication_remote_command_passed':result.returncode==0 and 'C80_SSH_READY' in result.stdout,
         'exit_status':result.returncode,'stdout':result.stdout,'stderr':result.stderr,
         'router_rootfs_changed':False,'QEMU_guest_IP_set_for_forwarding_only':True,
         'physical_router_SSH_login_tested':False,'commands':ns['results'],
         'rootfs_CPIO_sha256':hashlib.sha256((P/'build/usr/initramfs_data.cpio').read_bytes()).hexdigest()}
 (R/'evidence/ssh-result.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps({k:v for k,v in report.items() if k!='commands'},indent=2))
finally:
 process=ns['process']
 if process.poll() is None:process.terminate();process.wait(timeout=5)
 ns['rawlog'].close()
