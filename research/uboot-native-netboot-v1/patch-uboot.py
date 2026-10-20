#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Patch the ORIGINAL normal U-Boot reset vector and append its built-in hook.
No write to a router. No replacement of the original loader with a RAM wrapper.
"""
from pathlib import Path
import hashlib,json,lzma,struct,zlib
R=Path(__file__).resolve().parent
sha=lambda b:hashlib.sha256(b).hexdigest()
stock=(R.parent/'flash-full-20261017/installed/components/normal-uboot.bin').read_bytes()
image=(R.parent/'flash-full-20261017/installed/components/normal-uboot.uImage').read_bytes()
assert len(stock)==0x2f850 and sha(stock)=='5bc7b96397f63110f9f4b98c8fdfd46378c3be73c6f9431e1b35908135d62840'
assert stock[:4]==bytes.fromhex('0f0000ea') and lzma.decompress(image[64:],format=lzma.FORMAT_ALONE)==stock
hook=(R/'netboot-hook.bin').read_bytes()
assert 0<len(hook)<0x10000
# Actual stock _start at offset0 is changed to branch to its built-in extension.
# The original vector's target0x44 remains the fallback. Other OEM bytes and
# ALL original relocation/BSS markers are left byte-identical.
branch=0xea000000 | ((len(stock)-8)//4)
raw=struct.pack('<I',branch)+stock[4:]+hook
# Identical LZMA1 properties to OEM (lc3/lp0/pb2); a shorter encoder match
# search limit keeps the new BOOT+TPOS inside the existing MiniFS boundary.
filters=[{'id':lzma.FILTER_LZMA1,'dict_size':1<<23,'lc':3,'lp':0,'pb':2,
          'mode':lzma.MODE_NORMAL,'nice_len':48,'mf':lzma.MF_BT4,'depth':0}]
compressed=bytearray(lzma.compress(raw,format=lzma.FORMAT_ALONE,filters=filters))
compressed[5:13]=struct.pack('<Q',len(raw))
assert lzma.decompress(compressed,format=lzma.FORMAT_ALONE)==raw
fields=list(struct.unpack('>7I4B32s',image[:64]))
fields[1]=0;fields[3]=len(compressed);fields[6]=zlib.crc32(compressed)
fields[-1]=b'C80 U-Boot native AutoTFTP v1'.ljust(32,b'\0')
header=bytearray(struct.pack('>7I4B32s',*fields));struct.pack_into('>I',header,4,zlib.crc32(header))
patched=bytes(header)+compressed
(R/'private/normal-uboot-patched.bin').write_bytes(raw)
(R/'c80-uboot-native.uImage').write_bytes(patched)
report={'passed':True,'stock_raw_sha256':sha(stock),'stock_raw_bytes':len(stock),
 'patched_raw_sha256':sha(raw),'patched_raw_bytes':len(raw),'stock_prefix_bytes_preserved':len(stock)-4,
 'stock_instruction_patch':{'offset':'00000000','old':'ea00000f','new':f'{branch:08x}','target':'41c2f850'},
 'hook_bytes':len(hook),'hook_sha256':sha(hook),'fallback_original_start':'41c00044',
 'stock_relocation_and_BSS_bounds_unchanged':True,'hook_runs_before_stock_init_and_need_not_survive_BSS_clear':True,
 'uImage_bytes':len(patched),'uImage_sha256':sha(patched),'uImage_crc32':f'{zlib.crc32(patched):08x}',
 'load_and_entry':'41c00000','compressed_growth':len(patched)-len(image),'hardware_tested':False}
(R/'evidence').mkdir(exist_ok=True)
(R/'evidence/patch.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
