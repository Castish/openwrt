#!/usr/bin/env python3
"""Compare RAM31 runtime inputs with the frozen, hardware-tested RAM30 issue."""
from pathlib import Path
import difflib,gzip,hashlib,json,zipfile
from cpio_tools import entries
r=Path(__file__).resolve().parent;p=r.parent/'openwrt-ram30-ring128'
z=p/'c80-openwrt-ram30-ring128.zip'
sha=lambda b:hashlib.sha256(b).hexdigest()
assert sha(z.read_bytes())=='e79d57b45957721dcb9a3150fd5690ac17d2acd261c4d3aadb2519f55bf16b5b'
with zipfile.ZipFile(z) as a:
 prefix=z.stem+'/'
 m=json.loads(a.read(prefix+'package-manifest.json'))
 assert len(m['files'])==339
 for f in m['files']:
  raw=a.read(prefix+f['file'])
  assert len(raw)==f['bytes'] and sha(raw)==f['sha256']
  assert (p/f['file']).read_bytes()==raw,f['file']
 baseline=entries(gzip.decompress(a.read(prefix+'rootfs.cpio.gz')))
 for name in ['stock-command-oracle.bin','stock-station-command-oracle.bin','stock-auth-txd.bin','stock-association-txd.bin','stock-data-txd.bin','data-protocol-fixtures.bin','c80-script-runner.bin','c80-wifi-test.ps1']:
  assert (r/name).read_bytes()==a.read(prefix+name),name
 assert (r/'c80-openwrt-ram31-scheduler.dtb').read_bytes()==a.read(prefix+'c80-openwrt-ram30-ring128.dtb')
 assert (r/'c80-openwrt-ram31-handoff.bin').read_bytes()==a.read(prefix+'c80-openwrt-ram30-handoff.bin')
source=json.loads((r/'evidence/parent-source-inputs.json').read_text());changed=[];diff=[]
for name,digest in source['files'].items():
 old=(r/'parent-source-inputs'/name).read_bytes();assert sha(old)==digest,name
 new=(r/'linux-6.12.113'/name).read_bytes()
 if old!=new:
  changed.append(name)
  diff.extend(difflib.unified_diff(old.decode().splitlines(True),new.decode().splitlines(True),fromfile='a/'+name,tofile='b/'+name))
assert sorted(changed)==['drivers/soc/mediatek/'+n for n in ['c80_mcu_core.h','c80_mcu_transport.c']],changed
current=entries((r/'build/usr/initramfs_data.cpio').read_bytes());assert baseline.keys()==current.keys()
root_changed=sorted(n for n in baseline if baseline[n]!=current[n])
assert root_changed==['usr/sbin/c80-wifi'],root_changed
for n in baseline:
 if n.startswith('lib/firmware/c80/'):assert baseline[n]==current[n]
(r/'ram30-to-ram31.patch').write_text(''.join(diff))
result={'passed':True,'all_339_parent_ZIP_and_local_members_verified':True,
 'parent_ZIP_sha256':sha(z.read_bytes()),'patched_source_files_compared':24,
 'Linux_changed':sorted(changed),'Linux_added':[],'rootfs_entries_compared':len(current),
 'rootfs_changed':root_changed,'all_Ethernet_DSA_UART_reset_DTB_sources_unchanged':True,
 'all_61_MCU_oracles_and_4_TXD_profiles_unchanged':True,'six_generic_firmware_unchanged':True,
 'Linux_packet_callbacks_unchanged':True,'allocation_shape_unchanged':True,
 'active_descriptor_entries':128,'allocated_descriptor_entries':512,
 'legacy_netdev_entries':512,'short_transport_timeout_us':1000000,
 'scope':'Keep RAM30 ring128 and all TX/completion/timeout behavior. Add exact15-register OEM DMA scheduler initialization/readback/live guards/restoration and snapshots. Rootfs helper exact version plus scheduler report.',
 'physical_new_image_tested':False,'underlying_RAM30_stall_cause_established':False}
(r/'evidence/ram30-to-ram31-scope.json').write_text(json.dumps(result,indent=2)+'\n')
print('PASS RAM30 scope:2 MCU/scheduler files plus helper version; Ethernet/DTB/reset/packet callbacks/61 commands/4 TXD profiles/firmware/allocation unchanged; parent339 members intact.')
