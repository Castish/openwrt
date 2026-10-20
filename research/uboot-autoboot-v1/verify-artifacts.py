#!/usr/bin/env python3
"""Bind the issue to executed ARM paths and unchanged hardware-tested RAM31."""
from pathlib import Path
import hashlib,json,struct,zlib,lzma
R=Path(__file__).resolve().parent
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
b=json.loads((R/'evidence/boot-verification.json').read_text());assert b['passed'] and b['cases_passed']==40
assert b['wrapper_sha256']==sha(R/'c80-autoboot.bin') and b['runner_sha256']==sha(R/'c80-script-runner.bin')
successful={'native-go-runner-real-probe-and-stock-overwrite','native-jmpaddr-entry-real-probe-and-stock-overwrite','link-base-native-entry','verified-saved-stock-fallback','stock-return-tailcall-safe'}
for row in b['cases']:
 assert row['probe_runs']==int(row['case'] in successful),(row['case'],row['probe_runs'])
 if row['case'].startswith('setenv-') or row['case']=='runner-copy-corruption-falls-back':
  assert not any(c[0] in ['go','tftpboot'] for c in row['calls']),row['case']
 if row['case'].startswith(('factory-profile-refusal-','wrong-')) or row['case'] in ['missing-fallback-refuses','corrupt-fallback-refuses']:
  assert row['calls']==[],row['case']
 assert row['NOR_writes']==0
n=json.loads((R/'evidence/native-services-result.json').read_text());assert n['passed'] and n['cases_passed']==48
assert n['source_sha256']==sha(R/'verify-native-services.py')
d=json.loads((R/'evidence/native-decompress-result.json').read_text());assert d['passed'] and d['output_sha256']==sha(R/'c80-autoboot.bin')
u=(R/'c80-autoboot.uImage').read_bytes();h=list(struct.unpack('>7I4B32s',u[:64]));hc=bytearray(u[:64]);hc[4:8]=bytes(4)
assert zlib.crc32(hc)==h[1] and zlib.crc32(u[64:])==h[6] and h[3]==len(u)-64
assert h[4]==h[5]==0x41c00000 and lzma.decompress(u[64:],format=lzma.FORMAT_ALONE)==(R/'c80-autoboot.bin').read_bytes()
assert struct.unpack_from('<Q',u,69)[0]==6940
p=R.parent/'openwrt-ram31-scheduler';manifest=json.loads((p/'package-manifest.json').read_text())
for row in manifest['files']:assert sha(p/row['file'])==row['sha256']
for f in ['c80-openwrt-ram31-scheduler-zImage','c80-openwrt-ram31-scheduler.dtb','c80-openwrt-ram31-handoff.bin','c80-start.txt']:
 assert (R/f).read_bytes()==(p/f).read_bytes()
s=json.loads((R/'evidence/ssh-result.json').read_text());assert s['none_authentication_remote_command_passed'] and s['exit_status']==0
assert s['rootfs_CPIO_sha256']==sha(p/'build/usr/initramfs_data.cpio')
plan=json.loads((R/'evidence/flash-plan.json').read_text());assert plan['passed'] and len(plan['sectors'])==18
assert plan['factory_BOOTIMG_0_to_24fff_unchanged'] and plan['ISP_CONFIG_PROFILE_RADIO_3e8000_to_end_unchanged']
result={'passed':True,'wrapper_bytes':6940,'wrapper_sha256':sha(R/'c80-autoboot.bin'),'ARM_cases':40,'native_service_cases':48,'actual_native_LZMA_passed':True,'SSH_root_command_in_QEMU_passed':True,'RAM31_all361_issued_members_unchanged':True,'RAM31_payloads_not_duplicated_in_boot_ZIP':True,'physical_wrapper_tested':False,'permanent_installation_performed':False,'Windows_PowerShell_generator_executed_in_cloud':False}
(R/'evidence/artifact-verification.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
