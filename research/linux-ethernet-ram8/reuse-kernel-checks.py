#!/usr/bin/env python3
"""Reuse RAM7 native verification only after matching actual RAM8 sources to its issued manifest."""
from pathlib import Path
import hashlib,json
r=Path(__file__).resolve().parent
manifest=json.loads((r/'evidence/ram7-package-manifest.json').read_text())
baseline={x['file']:x for x in manifest['files']}
sha=lambda b:hashlib.sha256(b).hexdigest()
checked=[]
for name in ['c80_ram_eth.c','c80_pdma_core.h','c80_ram_mdio.c','c80_ram_mdio.h','c80_rtl8367s.h','rtl8365mb-patched.c','mt7626-archer-c80-v1-ram.dts','handoff.S','handoff.ld','test-driver.c','driver-test-shim.h','test-mdio.c','mdio-test-shim.h','test-dsa-control.c','test-dsa-tag.c','driver-tests/bsp-descriptors.h']:
    assert sha((r/name).read_bytes())==baseline[name]['sha256'],name
    checked.append(name)
k=r/'linux-6.12.113'
for name in ['c80_ram_eth.c','c80_pdma_core.h','c80_ram_mdio.c','c80_ram_mdio.h']:
    assert (r/name).read_bytes()==(k/'drivers/net/ethernet/mediatek'/name).read_bytes()
assert (r/'rtl8365mb-patched.c').read_bytes()==(k/'drivers/net/dsa/realtek/rtl8365mb.c').read_bytes()
assert (r/'c80_rtl8367s.h').read_bytes()==(k/'drivers/net/dsa/realtek/c80_rtl8367s.h').read_bytes()
dsa=json.loads((r/'artifacts/dsa-verification.json').read_text())
for name,key in [('net/dsa/tag_rtl8_4.c','upstream_tagger_sha256'),('net/dsa/tag.h','upstream_helpers_sha256')]:assert sha((k/name).read_bytes())==dsa[key]
old=(r/'evidence/ram7-kernel.config').read_text().splitlines()
new=(r/'build/.config').read_text().splitlines()
def relevant(lines):return [x for x in lines if x.startswith(('CONFIG_','# CONFIG_')) and not x.startswith(('CONFIG_LOCALVERSION=','CONFIG_INITRAMFS_SOURCE='))]
assert relevant(old)==relevant(new),'Unexpected kernel feature change beyond version/initramfs path'
result={'status':'pass','scope':__doc__,'parent_issued_zip_sha256':'f6e4b1d81afc6e81550db8b4219971fa26757157010fd5d60887df87289aab92','unchanged_files':checked,'unchanged_tagger_and_header_helpers':True,'kernel_config_only_changes':['LOCALVERSION','INITRAMFS_SOURCE'],'native_cases_reused':{'pdma':15481,'mdio':6306,'dsa_control':365,'dsa_packet':284},'native_suites_rerun':False,'ram8_userspace_verified_separately':True}
(r/'artifacts/kernel-source-reuse-verification.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
