#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Repack IMG0 around enlarged native U-Boot; preserve every other component."""
from pathlib import Path
import hashlib,json,struct,sys,zlib
R=Path(__file__).resolve().parent
sys.path.insert(0,str(R.parent))
from analyze_c80_flash import inspect
from analyze_c80_image import SLOTS
sha=lambda x:hashlib.sha256(x).hexdigest()
old=(R.parent/'flash-full-20261017/c80-full-flash.bin').read_bytes()
assert len(old)==0x400000 and zlib.crc32(old)==0xc9b76c54
before,_=inspect(old);img=before['img0'];slots=img['slots']
stock_body=old[0x25000:img['end']]
boot=(R/'c80-uboot-native.uImage').read_bytes()
pivot=slots['vximg']['offset_from_img0']
new_vx_offset=(0x80+len(boot)+3)&~3
shift=new_vx_offset-pivot
assert slots['boot']['offset_from_img0']==0x80 and shift>0
assert new_vx_offset+slots['vximg']['size']<=slots['minifs']['offset_from_img0']
body=bytearray(stock_body)
body[0x80:0x80+len(boot)]=boot
body[0x80+len(boot):new_vx_offset]=bytes(new_vx_offset-(0x80+len(boot)))
body[new_vx_offset:new_vx_offset+slots['vximg']['size']]=stock_body[pivot:pivot+slots['vximg']['size']]
for index,name in enumerate(SLOTS):
 s=slots[name];off,n=s['offset_from_img0'],s['size']
 if name=='vximg':off=new_vx_offset
 if name=='boot':n=len(boot)
 struct.pack_into('>II',body,64+index*8,off,n)
for name in ['signature','firmmd5']:
 i=SLOTS.index(name);a,n=struct.unpack_from('>II',body,64+i*8)
 body[a:a+n]=bytes(n)
md5off=struct.unpack_from('>I',body,64+SLOTS.index('firmmd5')*8)[0]
body[md5off:md5off+16]=hashlib.md5(body).digest()
new=bytearray(old);new[0x25000:0x25000+len(body)]=body
assert len(body)<0x3e8000-0x25000
assert old[:0x25000]==new[:0x25000] and old[0x3e8000:]==new[0x3e8000:]
after,blobs=inspect(bytes(new))
for name in SLOTS:
 if name in ('boot','firmmd5'):continue
 assert before['img0']['slots'][name]['sha256']==after['img0']['slots'][name]['sha256'],name
assert before['tpos']==after['tpos']
assert before['img0']['size']==after['img0']['size']
assert before['img0']['slots']['minifs']==after['img0']['slots']['minifs']
assert blobs['components/normal-uboot.bin']==(R/'private/normal-uboot-patched.bin').read_bytes()
original=old[0x25000:0x3e8000];modified=bytes(new[0x25000:0x3e8000])
(R/'c80-uboot-native-firmware.bin').write_bytes(modified)
(R/'c80-uboot-stock-firmware.bin').write_bytes(original)
rows=[]
for a in range(0x25000,0x3e8000,4096):
 x=old[a:a+4096];y=bytes(new[a:a+4096])
 if x!=y:rows.append({'offset':f'{a:06x}','old_crc32':f'{zlib.crc32(x):08x}','new_crc32':f'{zlib.crc32(y):08x}'})
report={'passed':True,'stock_FIRMWARE_sha256':sha(original),'new_FIRMWARE_sha256':sha(modified),
 'stock_FIRMWARE_crc32':f'{zlib.crc32(original):08x}','new_FIRMWARE_crc32':f'{zlib.crc32(modified):08x}',
 'FIRMWARE_bytes':len(original),'firmware_start':'25000','firmware_end_exclusive':'3e8000',
 'new_IMG0_bytes':len(body),'new_IMG0_end':f'{0x25000+len(body):x}',
 'TPOS_only_shift_bytes':shift,'changed_4KiB_sectors':len(rows),
 'MiniFS_offset_and_contents_unchanged':True,'IMG0_length_unchanged':True,
 'all_other_component_contents_preserved':True,'factory_BOOTIMG_preserved':True,
 'ISP_CONFIG_PROFILE_RADIO_preserved':True,'uImage_header_data_CRC_and_IMG0_MD5_pass':True,
 'old_slots':slots,'new_slots':after['img0']['slots'],'sectors':rows,'hardware_installed':False}
(R/'evidence/firmware.json').write_text(json.dumps(report,indent=2)+'\n')
(R/'install-profile.h').write_text(f'''/* Generated from verified old/new FIRMWARE. */
#define FW_START 0x25000u
#define FW_END 0x3e8000u
#define FW_LENGTH (FW_END-FW_START)
#define OLD_CRC 0x{zlib.crc32(original):08x}u
#define NEW_CRC 0x{zlib.crc32(modified):08x}u
#define FACTORY_CRC 0x{zlib.crc32(old[:0x25000]):08x}u
''')
print(json.dumps({k:v for k,v in report.items() if k not in ('old_slots','new_slots','sectors')},indent=2))
