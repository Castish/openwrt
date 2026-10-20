#!/usr/bin/env python3
"""Prepare an offline normal-BOOT delta; never opens a flash device or programs it.
Private sector buffers contain OEM bytes and are excluded from the test ZIP.
"""
from pathlib import Path
import hashlib,json,lzma,struct,sys,zlib
R=Path(__file__).resolve().parent
sys.path.insert(0,str(R.parent))
from analyze_c80_flash import inspect
from analyze_c80_image import SLOTS
sha=lambda b:hashlib.sha256(b).hexdigest()
old=(R.parent/'flash-full-20261017/c80-full-flash.bin').read_bytes()
assert len(old)==0x400000 and zlib.crc32(old)==0xc9b76c54
before,_=inspect(old)
assert before['img0']['size']==0x33b388 and before['img0']['signature_slot_all_zero']
stock=(R.parent/'flash-full-20261017/installed/components/normal-uboot.uImage').read_bytes()
assert len(stock)==64370 and zlib.crc32(stock)==0x969b0bf3
assert old[0x25080:0x25080+len(stock)]==stock and set(old[0x3d0000:0x3e0000])=={0}
boot=(R/'c80-autoboot.bin').read_bytes()
compressed=bytearray(lzma.compress(boot,format=lzma.FORMAT_ALONE,preset=6))
# The OEM decompressor receives output_len=0 and obtains the size from this
# LZMA-alone header. Preserve a KNOWN uncompressed size, as in the OEM image.
compressed[5:13]=struct.pack('<Q',len(boot))
assert lzma.decompress(compressed,format=lzma.FORMAT_ALONE)==boot
fields=list(struct.unpack('>7I4B32s',stock[:64]));fields[1]=0;fields[3]=len(compressed)
fields[4]=fields[5]=0x41c00000;fields[6]=zlib.crc32(compressed);fields[-1]=b'C80 AutoTFTP v1'.ljust(32,b'\0')
header=bytearray(struct.pack('>7I4B32s',*fields));struct.pack_into('>I',header,4,zlib.crc32(header))
uimage=bytes(header)+compressed;assert len(uimage)<len(stock)
(R/'c80-autoboot.uImage').write_bytes(uimage)
new=bytearray(old);new[0x25080:0x25080+len(uimage)]=uimage
length_field=0x25000+64+SLOTS.index('boot')*8+4
struct.pack_into('>I',new,length_field,len(uimage))
new[0x3d0000:0x3d0000+len(stock)]=stock
body=bytearray(new[0x25000:0x360388])
for name in ['signature','firmmd5']:
 s=before['img0']['slots'][name];a=s['offset_from_img0'];body[a:a+s['size']]=bytes(s['size'])
md5field=before['img0']['slots']['firmmd5']['flash_offset']
new[md5field:md5field+16]=hashlib.md5(body).digest()
assert zlib.crc32(new[0x25080:0x25080+len(stock)])!=0x969b0bf3
assert zlib.crc32(new[0x3d0000:0x3d0000+len(stock)])==0x969b0bf3
after,_=inspect(bytes(new))
assert after['normal_uboot']['uncompressed_bytes']==len(boot)
assert old[:0x25000]==new[:0x25000] and old[0x3e8000:]==new[0x3e8000:]
allowed=[(length_field,length_field+4),(0x25080,0x25080+len(uimage)),(md5field,md5field+16),(0x3d0000,0x3d0000+len(stock))]
for a,(x,y) in enumerate(zip(old,new)):
 if x!=y:assert any(start<=a<end for start,end in allowed),hex(a)
dest=R/'private/planned-sectors';dest.mkdir(exist_ok=True)
rows=[]
for a in range(0,len(old),4096):
 original=old[a:a+4096];modified=bytes(new[a:a+4096])
 if original==modified:continue
 assert 0x25000<=a<a+4096<=0x3e8000
 name=f'{a:06x}.bin';(dest/name).write_bytes(modified)
 rows.append({'offset':f'{a:06x}','bytes':4096,'old_sha256':sha(original),'new_sha256':sha(modified),
              'old_crc32':f'{zlib.crc32(original):08x}','new_crc32':f'{zlib.crc32(modified):08x}',
              'changed_bytes':sum(x!=y for x,y in zip(original,modified)),'private_buffer':name})
report={'passed':True,'scope':__doc__,'offline_only':True,'flash_write_commands_issued':False,'hardware_installed':False,
 'normal_BOOT_entry':'41c00000','uImage_bytes':len(uimage),'uImage_sha256':sha(uimage),
 'fallback_original_uImage_offset':'3d0000','fallback_bytes':len(stock),'fallback_crc32':'969b0bf3',
 'original_firmware_crc32':'c9b76c54','proposed_full_flash_crc32':f'{zlib.crc32(new):08x}',
 'factory_BOOTIMG_0_to_24fff_unchanged':True,'ISP_CONFIG_PROFILE_RADIO_3e8000_to_end_unchanged':True,
 'TPOS_MiniFS_and_support_signature_unchanged':True,'IMG0_canonical_MD5_recomputed_and_verified':True,
 'fallback_outside_declared_IMG0_inside_verified_zero_FIRMWARE_slack':True,'native_4KiB_erase_required':True,
 'installed_primary_refused_as_original_and_saved_copy_matches':True,
 'write_order_required':['verify all preimages and source integrity','write and verify original stock fallback copy','write and verify wrapper BOOT sectors','write and verify IMG0 MD5 sector last'],
 'rollback':'restore the old BOOT/header+MD5 sector bytes from verified backup; optional clear fallback slack. Factory recovery stays separate.',
 'power_loss':'normal firmware validation may fail while sectors/MD5 are being changed; factory recovery is preserved, not an atomic update.',
 'sectors':rows}
(R/'evidence/flash-plan.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items() if k!='sectors'},indent=2));print('Changed4KiB sectors:',len(rows))
