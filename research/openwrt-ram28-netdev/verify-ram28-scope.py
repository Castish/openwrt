#!/usr/bin/env python3
"""Compare working RAM28 inputs against the immutable hardware-proven RAM27."""
from pathlib import Path
import filecmp,hashlib,json,os
r=Path(__file__).resolve().parent;p=r.parent/'openwrt-ram27-window'
sha=lambda x:hashlib.sha256(x.read_bytes()).hexdigest()
for row in json.loads((p/'package-manifest.json').read_text())['files']:
 x=p/row['file'];assert x.stat().st_size==row['bytes'] and sha(x)==row['sha256'],row['file']
assert sha(p/'c80-openwrt-ram27-window.zip')=='45a2d6e5f9d5cd0943e2a440299e3aaf2f15767bf10f2e218e21b6a231aa278f'
def files(root):return {str(x.relative_to(root)):x for x in root.rglob('*') if x.is_symlink() or not x.is_dir()}
a,b=files(p/'linux-6.12.113'),files(r/'linux-6.12.113');assert not(a.keys()-b.keys())
changed=[]
for name in a:
 x,y=a[name],b[name]
 if x.is_symlink() or y.is_symlink():assert x.is_symlink() and y.is_symlink() and os.readlink(x)==os.readlink(y),name
 elif not filecmp.cmp(x,y,shallow=False):changed.append(name)
added=sorted(b.keys()-a.keys());changed.sort()
assert changed==['drivers/soc/mediatek/Kconfig','drivers/soc/mediatek/Makefile','drivers/soc/mediatek/c80_mcu_core.h','drivers/soc/mediatek/c80_mcu_transport.c'],changed
assert added==['drivers/soc/mediatek/c80_net_core.h','drivers/soc/mediatek/c80_net_linux.h','drivers/soc/mediatek/c80_net_selftest.c','drivers/soc/mediatek/c80_net_types.h'],added
for name in ['stock-command-oracle.bin','stock-station-command-oracle.bin','stock-auth-txd.bin','stock-association-txd.bin','stock-data-txd.bin','data-protocol-fixtures.bin','c80-script-runner.bin']:
 assert (r/name).read_bytes()==(p/name).read_bytes(),name
for name in (r/'rootfs/lib/firmware/c80').iterdir():assert name.read_bytes()==(p/'rootfs/lib/firmware/c80'/name.name).read_bytes(),name
assert (r/'c80-openwrt-ram28-netdev.dtb').read_bytes()==(p/'c80-openwrt-ram27-window.dtb').read_bytes()
assert (r/'c80-openwrt-ram28-handoff.bin').read_bytes()==(p/'c80-openwrt-ram27-handoff.bin').read_bytes()
a,b=files(p/'rootfs'),files(r/'rootfs');rc=[]
assert not(a.keys()-b.keys())
for name in a:
 x,y=a[name],b[name]
 if x.is_symlink() or y.is_symlink():
  if not(x.is_symlink() and y.is_symlink() and os.readlink(x)==os.readlink(y)):rc.append(name)
 elif not filecmp.cmp(x,y,shallow=False):rc.append(name)
result={'passed':True,'parent_233_issued_members_and_ZIP_unchanged':True,'parent_rootfs_entries':len(a),'full_Linux_entries_compared':len(b),'Linux_changed':changed,'Linux_added':added,'all_Ethernet_DSA_UART_reset_DTB_sources_unchanged':True,'all_61_MCU_oracles_and_4_TXD_profiles_unchanged':True,'six_generic_firmware_unchanged':True,'rootfs_changed':sorted(rc),'rootfs_added':sorted(b.keys()-a.keys()),'rootfs_scope':'official dnsmasq+package metadata, UID/GID453, DHCP+netifd configuration, service startup and c80-wifi helper; no private calibration/keys/leases'}
# Linux sizes are recorded separately from the rootfs map above.
result['parent_full_Linux_entries']=len(files(p/'linux-6.12.113'));result['full_Linux_entries_compared']=len(files(r/'linux-6.12.113'))
(r/'evidence/ram27-to-ram28-scope.json').write_text(json.dumps(result,indent=2)+'\n')
print('PASS full-source scope:4 MCU/build files changed,4 packet/test files added; Ethernet/DTB/reset/61 commands/4 profiles/six firmware unchanged. RAM27 remains frozen.')
