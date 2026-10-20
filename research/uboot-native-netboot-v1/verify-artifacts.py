#!/usr/bin/env python3
"""Cross-bind actual native patch, firmware, tests, manifest and frozen parents."""
from pathlib import Path
import hashlib,json,lzma,struct,zlib,zipfile
R=Path(__file__).resolve().parent
sha=lambda x:hashlib.sha256(x).hexdigest()
stock=(R.parent/'flash-full-20261017/installed/components/normal-uboot.bin').read_bytes()
image=(R/'c80-uboot-native.uImage').read_bytes();raw=lzma.decompress(image[64:],format=lzma.FORMAT_ALONE)
assert raw[4:len(stock)]==stock[4:] and raw[len(stock):]==(R/'netboot-hook.bin').read_bytes()
assert struct.unpack_from('<I',raw)[0]==0xea00be12
assert 0x41c00008+((struct.unpack_from('<I',raw)[0]&0xffffff)<<2)==0x41c2f850
header=bytearray(image[:64]);hcrc=struct.unpack_from('>I',header,4)[0];header[4:8]=bytes(4)
assert zlib.crc32(header)==hcrc
assert struct.unpack_from('>I',image,12)[0]==len(image)-64
assert struct.unpack_from('>I',image,24)[0]==zlib.crc32(image[64:])
assert struct.unpack_from('<Q',image,69)[0]==len(raw)
reports={name:json.loads((R/'evidence'/name).read_text()) for name in ['patch.json','firmware.json','boot-verification.json','installer-verification.json','native-decompress-result.json','native-services-result.json','oem-acceptance.json']}
for k,r in reports.items():assert r['passed'],k
assert reports['patch.json']['uImage_sha256']==sha(image)
assert reports['boot-verification.json']['patched_raw_sha256']==sha(raw) and reports['boot-verification.json']['cases_passed']==44
cases=reports['boot-verification.json']['cases']
assert any(x['case']=='actual-patched-vector-embedded-parser-native-go-real-probe' and x['probe_entries']==1 and x['original_stock_reset_reached'] for x in cases)
assert any(x['case']=='real-RAM31-manifest-three-files-to-real-handoff-entry' and x['application_entered'] and len([a for a in x['native_commands'] if a[0]=='tftpboot'])==4 for x in cases)
assert reports['native-decompress-result.json']['output_sha256']==sha(raw)
assert reports['native-services-result.json']['cases_passed']==410
assert reports['installer-verification.json']['cases_passed']==21
assert reports['installer-verification.json']['installer_sha256']==sha((R/'c80-uboot-install.bin').read_bytes())
fw=(R/'c80-uboot-native-firmware.bin').read_bytes();oldfw=(R/'c80-uboot-stock-firmware.bin').read_bytes()
assert sha(fw)==reports['firmware.json']['new_FIRMWARE_sha256']==reports['oem-acceptance.json']['firmware_sha256']
assert sha(oldfw)==reports['firmware.json']['stock_FIRMWARE_sha256']
assert fw[0x80:0x80+len(image)]==image
for op in ('install-all-changed-sectors-header-last','rollback-all-changed-sectors'):
 x=next(c for c in reports['installer-verification.json']['cases'] if c['case']==op)
 assert x['write_calls']==reports['firmware.json']['changed_4KiB_sectors'] and x['last_write']=='0x25000'
# Validate the ready-to-use manifest and immutable RAM31 payloads.
loads={};go=0
for line in (R/'c80-start.txt').read_text('ascii').splitlines():
 parts=line.split()
 if not parts or parts[0].startswith('#') or parts[0] in ('C80SCRIPT1','end'):continue
 if parts[0]=='load':
  assert len(parts)==5;a=int(parts[1],16);payload=(R/parts[2]).read_bytes()
  assert len(payload)==int(parts[3],16) and zlib.crc32(payload)==int(parts[4],16);loads[a]=parts[2]
 else:assert parts==['go','40e00000'];go+=1
assert len(loads)==3 and go==1
parents=[]
for dirname,zipname,expected in [
 ('openwrt-ram31-scheduler','c80-openwrt-ram31-scheduler.zip','805cd14bac690f3d4945c48d1cbd99ef09b8a7fcb74fe2e95fe997dd6f041479'),
 ('uboot-autoboot-v1','c80-autoboot-v1.zip','fd950ae74e0535a26d017079d42cbd1fcf86b6c2f5293915257a1403de9d31ac')]:
 p=R.parent/dirname;archive=p/zipname
 assert sha(archive.read_bytes())==expected
 m=json.loads((p/'package-manifest.json').read_text());rows=m['files']
 with zipfile.ZipFile(archive) as z:
  assert z.testzip() is None
  for row in rows:
   name=row['file'];data=(p/name).read_bytes();assert len(data)==row['bytes'] and sha(data)==row['sha256']
   prefix=z.namelist()[0].split('/')[0];key=prefix+'/'+name;assert z.read(key)==data,key
 parents.append({'directory':dirname,'ZIP_sha256':expected,'frozen_members_verified':len(rows)})
p=R.parent/'openwrt-ram31-scheduler'
for name in loads.values():assert (R/name).read_bytes()==(p/name).read_bytes()
assert sha((R.parent/'openwrt-ram28-netdev/README.md').read_bytes())=='5ecf5b9ba9e0966015931ca1ac21ba5f030cb6f7a24514ae497f465ee8d47fc2'
result={'passed':True,'native_Uboot_uImage_sha256':sha(image),'native_installer_sha256':sha((R/'c80-uboot-install.bin').read_bytes()),'parents':parents,'RAM31_payloads_unchanged':True,'standalone_runner_required':False,'user_RAM28_README_preserved':True,'reports_cross_bound':len(reports),'hardware_installed':False}
(R/'evidence/artifact-verification.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
