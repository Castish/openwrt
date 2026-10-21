#!/usr/bin/env python3
"""Real stock hostapd/nl80211 WPA2 handshake on a QEMU-only software backend.
Synthetic peer and key-install acceptance; no CCMP engine, MCU, DMA or RF.
"""
from pathlib import Path
import hashlib,hmac,json,os,struct,subprocess,time
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
R=Path(__file__).resolve().parent;P=R.parent/'openwrt-ram31-scheduler'
s=(P/'verify-qemu-network.py').read_text().split('\ntry:\n')[0]
s=s.replace("mode='linux-network'","mode='wpa2'").replace('base = Path(__file__).resolve().parent',f'base = Path({str(R)!r})').replace("str(base / 'run-qemu-emi-check.sh')",f"{str(R/'run-qemu-auth.sh')!r}")
ns={'__file__':str(__file__),'__name__':'wpa2_harness'};exec(compile(s,str(__file__),'exec'),ns)
checks=[];ssh=None;master=None
AA=bytes.fromhex('02c080280001');SPA=bytes.fromhex('02c080280002');RSN=bytes.fromhex('30140100000fac040100000fac040100000fac020000')
def check(name,condition):
 assert condition,name
 checks.append(name);print('PASS QEMU WPA2 '+name,flush=True)
def remote(cmd,data=None,okay=True):
 q=subprocess.run(ssh+[cmd],input=data,capture_output=True,timeout=25)
 if okay:assert q.returncode==0,(cmd,q.returncode,q.stderr.decode(errors='replace'),q.stdout.decode(errors='replace'))
 return q

def capture():return remote('cat /sys/kernel/c80_net_selftest/capture').stdout

def wait_eapol(message,timeout=8):
 deadline=time.monotonic()+timeout
 while time.monotonic()<deadline:
  p=capture()
  if len(p)<113 or p[12:14]!=b'\x88\x8e':continue
  p=p[14:];n=4+int.from_bytes(p[2:4],'big');p=p[:n]
  if len(p)<99 or p[1]!=3:continue
  info=int.from_bytes(p[5:7],'big')
  if message==1 and info&0x188==0x88:return p
  if message==3 and info&0x1c8==0x1c8:return p
 raise TimeoutError('real hostapd did not send EAPOL message '+str(message))

def prf(pmk,nonce,snonce):
 d=min(AA,SPA)+max(AA,SPA)+min(nonce,snonce)+max(nonce,snonce)
 return b''.join(hmac.new(pmk,b'Pairwise key expansion\0'+d+bytes([i]),hashlib.sha1).digest() for i in range(4))[:64]

def response(msg,kck,nonce,data=b'',four=False,bad=False):
 b=bytearray(struct.pack('!BBH',2,3,95+len(data))+bytes([2])+struct.pack('!HH',0x30a if four else 0x10a,16)+msg[9:17]+nonce+bytes(16+8+8+16)+struct.pack('!H',len(data))+data)
 assert len(b)==99+len(data)
 b[81:97]=hmac.new(kck,b,hashlib.sha1).digest()[:16]
 if bad:b[81]^=1
 return AA+SPA+b'\x88\x8e'+b

def status():return remote('cat /sys/kernel/c80_net_selftest/control').stdout.decode()

def handshake(cycle,bad=False):
 remote('echo 1 > /sys/kernel/c80_net_selftest/station')
 m1=wait_eapol(1);snonce=hashlib.sha256(('C80 synthetic WPA2 peer '+str(cycle)).encode()).digest()
 pmk=hashlib.pbkdf2_hmac('sha1',b'openwrt123',b'C80-RAM35',4096,32);ptk=prf(pmk,m1[17:49],snonce)
 check('peer-'+str(cycle)+'-unauthorized-before-M2','authorized=0' in status())
 remote('cat > /sys/kernel/c80_net_selftest/inject',response(m1,ptk[:16],snonce,RSN,bad=bad))
 if bad:
  time.sleep(.25);st=status();check('incorrect-M2-MIC-cannot-install-PTK-or-authorize','ptk=0 authorized=0' in st)
  return
 m3=wait_eapol(3);check('peer-'+str(cycle)+'-M3-ANonce-and-replay',m3[17:49]==m1[17:49] and m3[9:17]>=m1[9:17])
 raw=bytearray(m3);mic=bytes(raw[81:97]);raw[81:97]=bytes(16)
 check('peer-'+str(cycle)+'-real-hostapd-M3-MIC',hmac.compare_digest(mic,hmac.new(ptk[:16],raw,hashlib.sha1).digest()[:16]))
 info=int.from_bytes(m3[5:7],'big');check('peer-'+str(cycle)+'-M3-key-data-encrypted',bool(info&0x1000))
 size=int.from_bytes(m3[97:99],'big');plain=aes_key_unwrap(ptk[16:32],m3[99:99+size]);pos=0;gtk=None
 while pos+2<=len(plain):
  tag,n=plain[pos:pos+2]
  if tag==221 and n==0:break
  assert pos+2+n<=len(plain)
  val=plain[pos+2:pos+2+n]
  if tag==221 and val[:4]==bytes.fromhex('000fac01'):
   assert len(val)==22;gtk=val[6:]
  pos+=2+n
 check('peer-'+str(cycle)+'-real-M3-GTK-unwrapped',gtk is not None and len(gtk)==16)
 check('peer-'+str(cycle)+'-not-authorized-before-M4','authorized=0' in status())
 remote('cat > /sys/kernel/c80_net_selftest/inject',response(m3,ptk[:16],bytes(32),four=True))
 deadline=time.monotonic()+6
 while 'authorized=1' not in status():assert time.monotonic()<deadline
 check('peer-'+str(cycle)+'-authorized-after-valid-M4',True)
 remote('cat > /sys/kernel/c80_net_selftest/keycheck',ptk[32:48]);check('peer-'+str(cycle)+'-installed-TK-equals-independently-derived-PTK',True)
 st=remote('iw dev c80wlan0 station dump').stdout.decode();check('peer-'+str(cycle)+'-standard-authorized-station','authorized:\tyes' in st or 'authorized: yes' in st)

try:
 ns['receive_until'](b'Please press Enter to activate this console.',timeout=60)
 ns['send']('');ns['receive_until'](ns['prompt']);ns['send']('');ns['receive_until'](ns['prompt'])
 cmd=ns['command'];cmd('network','ubus -t 45 wait_for network');cmd('management','ifconfig eth0 192.168.0.1 netmask 255.255.255.0 up')
 cmd('private-initrd-unpacked','test -s /etc/dropbear/dropbear_ed25519_host_key')
 keys=json.loads((R.parent/'ssh-identity-v1/ssh-host-public.json').read_text())['host_keys'];known=R/'private/qemu-known-hosts';known.write_text(''.join('[127.0.0.1]:40223 '+x['public_key']+'\n' for x in keys))
 ask=R/'private/qemu-askpass.sh';ask.write_text("#!/bin/sh\nprintf '%s\\n' openwrt\n");ask.chmod(0o700)
 env=dict(os.environ,SSH_ASKPASS=str(ask),SSH_ASKPASS_REQUIRE='force',DISPLAY=':c80-test')
 socket=R/'private/qemu-ssh-socket';socket.unlink(missing_ok=True)
 options=['ssh','-F','/dev/null','-p','40223','-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no','-o','UserKnownHostsFile='+str(known),'-o','PreferredAuthentications=password','-o','PubkeyAuthentication=no','-o','NumberOfPasswordPrompts=1','-o','HostKeyAlgorithms=ssh-ed25519']
 master=subprocess.run(options+['-M','-S',str(socket),'-fN','root@127.0.0.1'],env=env,stdin=subprocess.DEVNULL,capture_output=True,start_new_session=True,timeout=20);assert master.returncode==0,master.stderr
 ssh=options+['-S',str(socket),'root@127.0.0.1'];check('strict-pinned-SSH-password-login',remote('id -u').stdout.strip()==b'0')
 phy=remote('iw phy').stdout;(R/'private/qemu-wiphy.txt').write_bytes(phy)
 check('real-AP-wiphy-present',b'* AP' in phy)
 remote('. /usr/libexec/c80-wifi-lifecycle.sh; c80_wifi_network_prepare /sys/kernel/c80_net_selftest/control')
 check('real-netifd-interface-already-up-before-AP',b'"up": true' in remote('ubus call network.interface.wifi_ram status').stdout)
 remote('. /usr/libexec/c80-wifi-lifecycle.sh; c80_wifi_network_prepare /sys/kernel/c80_net_selftest/control')
 check('network-prepare-idempotent-before-AP',True)
 remote('/etc/init.d/c80-hostapd start');remote('ubus -t 10 wait_for hostapd; sleep 1')
 remote("cp /etc/c80-hostapd.conf /tmp/wpa2.conf; printf 'bssid=%s\\n' \"$(cat /sys/class/net/c80wlan0/address)\" >> /tmp/wpa2.conf")
 remote("ubus call hostapd config_set '{\"phy\":\"phy0\",\"radio\":-1,\"config\":\"/tmp/wpa2.conf\"}'")
 time.sleep(.3);log=remote('logread -e hostapd').stdout;check('stock-hostapd-WPA2-AP-enabled',b'AP-ENABLED' in log)
 remote('/etc/init.d/dnsmasq restart; sleep 1')
 remote('. /usr/libexec/c80-wifi-lifecycle.sh; c80_wifi_assert_active /sys/kernel/c80_net_selftest/control')
 check('actual-helper-keeps-AP-after-DHCP-setup','starts=1 stops=0 active=1 finished=0' in status())
 q=remote('. /usr/libexec/c80-wifi-lifecycle.sh; c80_wifi_network_prepare /sys/kernel/c80_net_selftest/control',okay=False)
 check('actual-helper-refuses-network-reload-while-AP-active',q.returncode!=0)
 remote('. /usr/libexec/c80-wifi-lifecycle.sh; c80_wifi_assert_active /sys/kernel/c80_net_selftest/control')
 check('refused-network-reload-left-AP-running','starts=1 stops=0 active=1 finished=0' in status())
 arp=bytes.fromhex('ffffffffffff')+SPA+bytes.fromhex('08060001080006040001')+SPA+bytes([192,168,2,2])+bytes(6)+bytes([192,168,2,1])
 q=remote('cat > /sys/kernel/c80_net_selftest/inject',arp,okay=False);check('Linux-IP-port-closed-before-handshake',q.returncode!=0)
 handshake(1,bad=True);remote('echo 0 > /sys/kernel/c80_net_selftest/station');time.sleep(.1)
 handshake(2)
 q=remote('/usr/sbin/c80-net-selftest');check('authorized-real-Linux-DHCP-ARP-ICMP-UDP-TCP-stack',b'PASS LINUX-NETWORK 13' in q.stdout)
 remote('echo 0 > /sys/kernel/c80_net_selftest/station');time.sleep(.1)
 check('peer-delete-closes-controlled-port-and-clears-PTK','ptk=0 authorized=0' in status())
 handshake(3)
 log=remote('logread -e hostapd').stdout.decode();check('two-real-hostapd-authorized-connections',log.count('AP-STA-CONNECTED')==2)
 check('AP-kept-running-between-clients','starts=1 stops=0 active=1 finished=0' in status())
 before=status();remote('/etc/init.d/c80-hostapd stop');time.sleep(.2);check('normal-stop-through-real-nl80211', 'starts=1 stops=1 active=0 finished=1' in status())
 q=remote('. /usr/libexec/c80-wifi-lifecycle.sh; c80_wifi_assert_active /sys/kernel/c80_net_selftest/control',okay=False)
 check('actual-helper-refuses-success-after-AP-stopped',q.returncode!=0)
 mem=remote('cat /proc/meminfo').stdout.decode();available=int(next(x.split()[1] for x in mem.splitlines() if x.startswith('MemAvailable:')));check('QEMU-32MiB-memory-headroom',available>4096)
 (R/'evidence/qemu-wpa2-result.json').write_text(json.dumps({'passed':True,'cases_passed':len(checks),'cases':checks,'real_unmodified_hostapd_four_way_handshake':True,'independent_PMK_PTK_M2_M4_M3_MIC_AES_unwrap':True,'wrong_MIC_refused':True,'real_Linux_protocol_cases':13,'strict_pinned_SSH_password_cases':1,'state_before_stop':before,'memory_available_KiB':available,'synthetic_key_install_backend':True,'physical_MCU_CCMP_DMA_RF_emulated':False,'hardware_tested':False,'verification_source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'hostapd_sha256':hashlib.sha256((R/'rootfs/usr/sbin/hostapd').read_bytes()).hexdigest(),'kernel_sha256':hashlib.sha256((R/'build-qemu/arch/arm/boot/zImage').read_bytes()).hexdigest()},indent=2)+'\n')
 print('PASS real stock hostapd WPA2 handshake and Linux network; synthetic backend only.',flush=True)
finally:
 if ssh:
  try:
   (R/'private/qemu-hostapd-wpa2.log').write_bytes(remote('logread -e hostapd',okay=False).stdout)
   (R/'private/qemu-network-diagnostics.txt').write_bytes(remote('ifconfig c80wlan0; ubus call network.interface.wifi_ram status; ubus call service list; logread -e dnsmasq',okay=False).stdout)
  except Exception as e:print('log collection:',str(e),flush=True)
  subprocess.run(ssh[:-1]+['-O','exit','root@127.0.0.1'],capture_output=True,timeout=5)
 if ns['process'].poll() is None:ns['process'].terminate();ns['process'].wait(timeout=5)
 ns['rawlog'].close()
