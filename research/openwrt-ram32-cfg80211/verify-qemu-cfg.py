#!/usr/bin/env python3
"""Real cfg80211/hostapd on QEMU-only synthetic backend; no MCU/RF emulation."""
from pathlib import Path
import json,subprocess,os,time,sys,hashlib
R=Path(__file__).resolve().parent;P=R.parent/'openwrt-ram31-scheduler'
fault='--fault' in sys.argv
mode='fault' if fault else 'normal'
s=(P/'verify-qemu-network.py').read_text().split('\ntry:\n')[0]
s=s.replace("mode='linux-network'",f"mode='cfg80211-{mode}'")
s=s.replace('base = Path(__file__).resolve().parent',f'base = Path({str(R)!r})')
s=s.replace("str(base / 'run-qemu-emi-check.sh')",f"{str(R/'run-qemu-auth.sh')!r}")
ns={'__file__':str(__file__),'__name__':'cfg80211_harness'};exec(compile(s,str(__file__),'exec'),ns)
try:
 ns['receive_until'](b'Please press Enter to activate this console.',timeout=60)
 ns['send']('');ns['receive_until'](ns['prompt']);ns['send']('');ns['receive_until'](ns['prompt'])
 command=ns['command']
 command('network-ready','ubus -t 45 wait_for network')
 command('virtual-management','ifconfig eth0 192.168.0.1 netmask 255.255.255.0 up')
 command('initrd-was-unpacked','test -s /etc/dropbear/dropbear_ed25519_host_key')
 assert b'Unpacking initramfs...' in ns['all_output'] and b'INITRD:' not in ns['all_output']
 command('hostapd-version','hostapd -v 2>&1 || test "$?" -eq 1','hostapd v')
 command('registered-real-wiphy','iw phy','Supported interface modes:')
 command('real-nl80211-interface','iw dev c80wlan0 info','type AP')
 # Debug log is always collected in finally if AP setup fails.
 command('reject-station-mode',"if iw dev c80wlan0 set type managed;then false;else true;fi")
 command('AP-mode-preserved','iw dev c80wlan0 info','type AP')
 command('reject-second-interface',"if iw phy phy0 interface add c80-extra type __ap;then false;else true;fi")
 command('no-extra-netdev','test ! -e /sys/class/net/c80-extra')
 command('down-for-address-check','ifconfig c80wlan0 down')
 command('same-address-idempotent','ifconfig c80wlan0 hw ether "$(cat /sys/class/net/c80wlan0/address)"')
 command('reject-unprogrammed-address',"if ifconfig c80wlan0 hw ether 02:c0:80:32:00:ff;then false;else true;fi")
 command('address-remains-correct',"grep -q '02:c0:80:28:00:01' /sys/class/net/c80wlan0/address")
 command('up-again','ifconfig c80wlan0 up')
 command('start-supervised-stock-hostapd','/etc/init.d/c80-hostapd start')
 command('supervised-daemon-running',"ubus call service list '{\"name\":\"c80-hostapd\"}'",'"running": true')
 command('global-hostapd-ready','ubus -t 10 wait_for hostapd; sleep 1')
 command('runtime-BSSID-from-device',"cp /etc/c80-hostapd.conf /tmp/cfg-hostapd.conf; printf 'bssid=%s\\n' \"$(cat /sys/class/net/c80wlan0/address)\" >> /tmp/cfg-hostapd.conf")
 command('configure-through-standard-ubus',"ubus call hostapd config_set '{\"phy\":\"phy0\",\"radio\":-1,\"config\":\"/tmp/cfg-hostapd.conf\"}'")
 command('wait-for-AP','sleep 1')
 command('AP-enabled','logread -e hostapd','AP-ENABLED')
 command('new-station-notification','echo 1 > /sys/kernel/c80_net_selftest/station')
 command('standard-station-query','iw dev c80wlan0 station dump','Station 02:c0:80:28:00:02')
 command('hostapd-station-event','logread -e hostapd','AP-STA-CONNECTED')
 if fault:
  command('synthetic-unsolicited-stop-notification','echo 2 > /sys/kernel/c80_net_selftest/station')
  command('wait-for-stop-event','sleep 1')
  command('kernel-STOP-event-called-real-stop-ap','cat /sys/kernel/c80_net_selftest/control','starts=1 stops=1 active=0 finished=1')
  # Stock hostapd logs STOP_AP; the helper closes its procd service on completion.
  command('close-finished-transport-service','/etc/init.d/c80-hostapd stop')
 else:
  command('normal-supervised-hostapd-stop','/etc/init.d/c80-hostapd stop')
 command('wait-clean-daemon-exit','sleep 1')
 command('AP-disabled','logread -e hostapd','AP-DISABLED')
 command('station-removed','test -z "$(iw dev c80wlan0 station dump)"')
 command('memory','free')
 keys=json.loads((R.parent/'ssh-identity-v1/ssh-host-public.json').read_text())['host_keys']
 known=R/'private/qemu-known-hosts';known.write_text(''.join('[127.0.0.1]:40223 '+k['public_key']+'\n' for k in keys))
 ask=R/'private/qemu-askpass.sh';ask.write_text("#!/bin/sh\nprintf '%s\\n' openwrt\n");ask.chmod(0o700)
 env=dict(os.environ,SSH_ASKPASS=str(ask),SSH_ASKPASS_REQUIRE='force',DISPLAY=':c80-test')
 for algo in ['ssh-ed25519','rsa-sha2-256']:
  result=subprocess.run(['ssh','-F','/dev/null','-p','40223','-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no',
   '-o','UserKnownHostsFile='+str(known),'-o','PreferredAuthentications=password','-o','PubkeyAuthentication=no',
   '-o','NumberOfPasswordPrompts=1','-o','HostKeyAlgorithms='+algo,'root@127.0.0.1','id -u'],
   env=env,stdin=subprocess.DEVNULL,capture_output=True,text=True,start_new_session=True,timeout=20)
  assert result.returncode==0 and result.stdout.strip()=='0',(algo,result.stdout,result.stderr)
 assert b'WARNING: CPU:' not in ns['all_output'] and b'Kernel panic' not in ns['all_output']
 (R/('evidence/qemu-cfg80211-'+mode+'-result.json')).write_text(json.dumps({'passed':True,'real_Linux_cfg80211_and_nl80211':True,'unmodified_signed_OpenWrt_hostapd':True,'synthetic_backend_only':True,'hardware_tested':False,'mode':mode,'strict_pinned_SSH_password_cases':2,'hostapd_SHA256':hashlib.sha256((R/'rootfs/usr/sbin/hostapd').read_bytes()).hexdigest(),'qemu_kernel_SHA256':hashlib.sha256((R/'build-qemu/arch/arm/boot/zImage').read_bytes()).hexdigest(),'commands':ns['results']},indent=2)+'\n')
 print('PASS real cfg80211/nl80211/hostapd open AP and station events; synthetic transport only.',flush=True)
finally:
 if ns['process'].poll() is None:
  try:
   ns['send']('logread -e hostapd');output=ns['receive_until'](ns['prompt'],timeout=10)
   (R/('evidence/qemu-hostapd-'+mode+'.log')).write_text(output)
  except Exception as e:print('Could not collect daemon log:',e,flush=True)
  ns['process'].terminate();ns['process'].wait(timeout=5)
 ns['rawlog'].close()
