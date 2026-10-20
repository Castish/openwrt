#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Issue exactly the reviewed native U-Boot/installer and unchanged RAM31 files."""
from pathlib import Path
import hashlib,json,zipfile
R=Path(__file__).resolve().parent;output=R/'c80-uboot-native-v1.zip'
assert not output.exists(),'Issued artifacts are immutable; use a new directory.'
files=['README.md','LICENSES.md','PROVENANCE.json','Set-C80Boot.ps1','c80-start.txt',
 'c80-uboot-native.uImage','c80-uboot-native-firmware.bin','c80-uboot-stock-firmware.bin','c80-uboot-install.bin',
 'c80-openwrt-ram31-scheduler-zImage','c80-openwrt-ram31-scheduler.dtb','c80-openwrt-ram31-handoff.bin',
 'entry.S','netboot.c','hook.ld','netboot-hook.bin','build.sh','patch-uboot.py','make-firmware.py',
 'install.c','install-entry.S','install.ld','install-profile.h','symbols.txt','disassembly.txt','elf-inspection.txt',
 'installer-symbols.txt','installer-disassembly.txt','verify-boot.py','verify-installer.py','verify-native-decompress.py',
 'verify-native-services.py','verify-oem-acceptance.py','verify-artifacts.py','package.py',
 'build-result.log','boot-verification.log','installer-verification.log','native-decompress-verification.log',
 'native-services-verification.log','oem-acceptance.log','artifact-verification.log']
for name in ['patch','firmware','boot-verification','installer-verification','native-decompress-result','native-services-result','oem-acceptance','artifact-verification']:
 files.append('evidence/'+name+'.json')
assert len(set(files))==len(files) and all((R/n).is_file() for n in files)
sha=lambda data:hashlib.sha256(data).hexdigest()
(R/'SHA256SUMS').write_text(''.join(f'{sha((R/n).read_bytes())}  {n}\n' for n in sorted(files)))
files.append('SHA256SUMS')
manifest={'release':'C80 native normal U-Boot AutoTFTP v1','hardware_installed':False,
 'frozen_issued_members':True,'full_flash_factory_loader_and_calibration_included':False,
 'normal_UBoot_and_required_FIRMWARE_install_rollback_images_included':True,
 'files':[{'file':n,'bytes':(R/n).stat().st_size,'sha256':sha((R/n).read_bytes())} for n in sorted(files)]}
(R/'package-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
files.append('package-manifest.json')
with zipfile.ZipFile(output,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
 for n in sorted(files):
  assert not n.startswith(('private/','hardware-')) and n!='STATUS.md'
  z.write(R/n,'c80-uboot-native-v1/'+n)
with zipfile.ZipFile(output) as z:
 assert z.testzip() is None
 for row in manifest['files']:assert sha(z.read('c80-uboot-native-v1/'+row['file']))==row['sha256']
result={'passed':True,'ZIP':output.name,'bytes':output.stat().st_size,'sha256':sha(output.read_bytes()),
 'archive_files':len(files),'frozen_members':len(manifest['files']),'hardware_installed':False}
(R/'bundle-result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
