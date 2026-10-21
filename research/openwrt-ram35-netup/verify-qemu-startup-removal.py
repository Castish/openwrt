#!/usr/bin/env python3
"""Inject the empty hostapd config seen in the owner's RAM34 log.
Real hostapd/cfg80211/OpenWrt; QEMU-only synthetic C80 key backend.
This tests the observed removal action, not the hardware timing of ifup.
"""
from pathlib import Path
import hashlib,json,time
R=Path(__file__).resolve().parent;P=R.parent/'openwrt-ram31-scheduler'
s=(P/'verify-qemu-network.py').read_text().split('\ntry:\n')[0].replace("mode='linux-network'","mode='startup-removal'").replace('base = Path(__file__).resolve().parent',f'base = Path({str(R)!r})').replace("str(base / 'run-qemu-emi-check.sh')",f'{str(R/"run-qemu-auth.sh")!r}')
n={'__file__':str(__file__),'__name__':'startup_removal'};exec(compile(s,str(__file__),'exec'),n)
try:
 n['receive_until'](b'Please press Enter to activate this console.',timeout=60);n['send']('');n['receive_until'](n['prompt']);n['send']('');n['receive_until'](n['prompt']);c=n['command']
 c('network-ready','ubus -t 45 wait_for network')
 c('source-real-helper','. /usr/libexec/c80-wifi-lifecycle.sh')
 c('prepare-before-AP','c80_wifi_network_prepare /sys/kernel/c80_net_selftest/control')
 c('netifd-up-before-AP','ubus call network.interface.wifi_ram status','"up": true')
 c('start-hostapd','/etc/init.d/c80-hostapd start; ubus -t 10 wait_for hostapd; sleep 1')
 c('runtime-config',"cp /etc/c80-hostapd.conf /tmp/removal.conf; printf 'bssid=%s\\n' \"$(cat /sys/class/net/c80wlan0/address)\" >> /tmp/removal.conf")
 c('start-AP',"ubus call hostapd config_set '{\"phy\":\"phy0\",\"radio\":-1,\"config\":\"/tmp/removal.conf\"}'")
 c('assert-real-AP-active','c80_wifi_assert_active /sys/kernel/c80_net_selftest/control')
 c('inject-owner-observed-empty-configuration',"ubus call hostapd config_set '{\"phy\":\"phy0\",\"radio\":-1,\"config\":\"\"}'; sleep 1")
 c('real-STOP-AP-observed','cat /sys/kernel/c80_net_selftest/control','starts=1 stops=1 active=0 finished=1')
 c('new-helper-rejects-false-start-success','if c80_wifi_assert_active /sys/kernel/c80_net_selftest/control; then false; else true; fi','AP is no longer active')
 c('new-helper-refuses-prepare-after-finished','if c80_wifi_network_prepare /sys/kernel/c80_net_selftest/control; then false; else true; fi','AP test has finished')
 c('real-hostapd-removal-log','logread -e hostapd','AP-DISABLED')
 d={'passed':True,'commands_passed':len(n['results']),'checks':n['results'],'owner_observed_empty_config_injected':True,'real_hostapd_cfg80211_STOP_AP':True,'actual_shared_helper_rejected_false_success':True,'hardware_ifup_timing_reproduced':False,'synthetic_key_install_backend':True,'hardware_tested':False,'verification_source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'lifecycle_source_sha256':hashlib.sha256((R/'c80_wifi_lifecycle.sh').read_bytes()).hexdigest(),'kernel_sha256':hashlib.sha256((R/'build-qemu/arch/arm/boot/zImage').read_bytes()).hexdigest()}
 (R/'evidence/qemu-startup-removal-result.json').write_text(json.dumps(d,indent=2)+'\n');print('PASS: '+str(len(n['results']))+' real OpenWrt empty-config/removal/helper-guard checks; synthetic radio backend.',flush=True)
finally:
 if n['process'].poll() is None:n['process'].terminate();n['process'].wait(timeout=5)
 n['rawlog'].close()
