#!/usr/bin/env python3
"""Two independent QEMU32MiB boots of unchanged RAM31 userspace/kernel plus
external per-device4KiB auth initramfs at the exact proposed RAM address.
Tests real Dropbear password authentication with pinned ED25519/RSA-SHA256
server keys and checks all three key files. C80 Ethernet/radio/NOR are not emulated.
"""
from pathlib import Path
import hashlib,json,os,subprocess,time
R=Path(__file__).resolve().parent;P=R.parent/'openwrt-ram31-scheduler'
os.umask(0o077);private=R/'private';private.mkdir(exist_ok=True)
keys=json.loads((R/'ssh-host-public.json').read_text())['host_keys']
known=private/'qemu-known-hosts'
known.write_text(''.join('[127.0.0.1]:40223 '+x['public_key']+'\n' for x in keys));known.chmod(0o600)
helpers={}
for name,pw in [('right','openwrt'),('wrong','deliberately-wrong')]:
 p=private/('askpass-'+name+'.sh');p.write_text("#!/bin/sh\nprintf '%s\\n' '"+pw+"'\n");p.chmod(0o700);helpers[name]=p
allcases=[];boots=[]
for boot in [1,2]:
 s=(P/'verify-qemu-network.py').read_text().split('\ntry:\n')[0]
 s=s.replace("mode='linux-network'",f"mode='stable-password-{boot}'")
 s=s.replace('base = Path(__file__).resolve().parent',f'base = Path({str(P)!r})')
 s=s.replace("evidence = base / 'evidence'",f"evidence = Path({str(R/'evidence')!r})")
 s=s.replace("str(base / 'run-qemu-emi-check.sh')",f"{str(R/'run-qemu-auth.sh')!r}")
 ns={'__file__':str(__file__),'__name__':'qemu_auth_harness'}
 exec(compile(s,str(__file__),'exec'),ns)
 try:
  ns['receive_until'](b'Please press Enter to activate this console.',timeout=60)
  ns['send']('');ns['receive_until'](ns['prompt']);ns['send']('');ns['receive_until'](ns['prompt'])
  ns['command']('network-ready','ubus -t 45 wait_for network')
  ns['command']('virtual-management-LAN','ifconfig eth0 192.168.0.1 netmask 255.255.255.0 up')
  ns['command']('dropbear-running',"ubus call service list '{\"name\":\"dropbear\"}'",'"running": true')
  ns['command']('overlay-host-key-present','test -s /etc/dropbear/dropbear_ed25519_host_key')
  ns['command']('overlay-shadow-present',"grep -q '^root:\\$6\\$' /etc/shadow")
  assert b'Unpacking initramfs...' in ns['all_output']
  assert b'Initramfs unpacking failed' not in ns['all_output']
  for key in keys:
   name='dropbear_'+key['type']+'_host_key'
   digest=hashlib.sha256((private/'identity'/name).read_bytes()).hexdigest()
   ns['command']('unchanged-'+key['type']+'-host-key','sha256sum /etc/dropbear/'+name,digest)
  # This small OpenWrt Dropbear build offers ED25519 and RSA-SHA256;
  # ECDSA and RSA-SHA512 are not compiled in. Do not change the router daemon.
  for algorithm in ['ssh-ed25519','rsa-sha2-256']:
   env=dict(os.environ);env.update(SSH_ASKPASS=str(helpers['right']),SSH_ASKPASS_REQUIRE='force',DISPLAY=':c80-auth-test')
   cmd=['ssh','-F','/dev/null','-p','40223','-o','ConnectTimeout=8','-o','PreferredAuthentications=password',
        '-o','PubkeyAuthentication=no','-o','NumberOfPasswordPrompts=1','-o','StrictHostKeyChecking=yes',
        '-o','UpdateHostKeys=no','-o','UserKnownHostsFile='+str(known),'-o','HostKeyAlgorithms='+algorithm,
        'root@127.0.0.1',"printf 'C80_PASSWORD_OK\\n'; id -u; uname -r"]
   result=subprocess.run(cmd,env=env,stdin=subprocess.DEVNULL,capture_output=True,text=True,start_new_session=True,timeout=25)
   assert result.returncode==0 and 'C80_PASSWORD_OK\n0\n' in result.stdout,(boot,algorithm,result.stdout,result.stderr)
   allcases.append({'boot':boot,'case':'password-openwrt-and-pinned-host-key','algorithm':algorithm,'exit_status':result.returncode,'stdout':result.stdout,'stderr':result.stderr,'passed':True})
  for method in ['wrong-password','none-authentication']:
   cmd=['ssh','-F','/dev/null','-p','40223','-o','ConnectTimeout=8','-o','PubkeyAuthentication=no',
        '-o','NumberOfPasswordPrompts=1','-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no',
        '-o','UserKnownHostsFile='+str(known),'-o','HostKeyAlgorithms=ssh-ed25519']
   env=dict(os.environ)
   if method=='wrong-password':
    cmd+=['-o','PreferredAuthentications=password'];env.update(SSH_ASKPASS=str(helpers['wrong']),SSH_ASKPASS_REQUIRE='force',DISPLAY=':c80-auth-test')
   else:cmd+=['-o','BatchMode=yes','-o','PreferredAuthentications=none']
   cmd+=['root@127.0.0.1','true']
   result=subprocess.run(cmd,env=env,stdin=subprocess.DEVNULL,capture_output=True,text=True,start_new_session=True,timeout=25)
   assert result.returncode!=0 and 'Permission denied' in result.stderr,(boot,method,result.stdout,result.stderr)
   assert 'Host key verification failed' not in result.stderr
   allcases.append({'boot':boot,'case':method+'-refused','exit_status':result.returncode,'stderr':result.stderr,'passed':True})
  ns['command']('router-helper-still-present','c80-wifi status','Not started.')
  ns['command']('memory-status','free')
  boots.append({'boot':boot,'commands':ns['results'],'external_initramfs_detected':True,'all_three_key_files_unchanged':True,'both_supported_server_algorithms_accepted_from_same_preexisting_pin_file':True})
  print(f'PASS boot{boot}: password accepted; ED25519/RSA-SHA256 host identity unchanged; wrong/empty auth refused.',flush=True)
 finally:
  process=ns['process']
  if process.poll() is None:process.terminate();process.wait(timeout=5)
  ns['rawlog'].close()
report={'passed':True,'scope':__doc__,'cold_virtual_boots':2,'SSH_cases_passed':len(allcases),'cases':allcases,'boots':boots,
 'host_key_checking':'strict=yes, pre-pinned from locally generated public keys before boot1; same file boot2',
 'client_private_key_used':False,'password_authentication_required':True,
 'CPIO_sha256':hashlib.sha256((R/'c80-auth.cpio').read_bytes()).hexdigest(),
 'parent_hardware_kernel_sha256':hashlib.sha256((P/'c80-openwrt-ram31-scheduler-zImage').read_bytes()).hexdigest(),
 'parent_hardware_rootfs_CPIO_sha256':hashlib.sha256((P/'build/usr/initramfs_data.cpio').read_bytes()).hexdigest(),
 'parent_QEMU_rootfs_CPIO_sha256':hashlib.sha256((P/'build-qemu/usr/initramfs_data.cpio').read_bytes()).hexdigest(),
 'hardware_router_tested':False,'flash_writes':0}
(R/'evidence/auth-verification.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS two boots /8 real SSH cases; no host-key reacceptance and no client key.',flush=True)
