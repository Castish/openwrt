#!/usr/bin/env python3
"""Pin unchanged RAM8 kernel/data-path sources; verify the exact isolated ECO guard change and rerun/report scope."""
from pathlib import Path
import hashlib,json,difflib
r=Path(__file__).resolve().parent;sha=lambda b:hashlib.sha256(b).hexdigest()
baseline=json.loads((r/'evidence/ram8-package-manifest.json').read_text());entries={x['file']:x for x in baseline['files']}
checked=[]
for name in ['c80_ram_eth.c','c80_pdma_core.h','c80_ram_mdio.c','c80_ram_mdio.h','rtl8365mb-patched.c','mt7626-archer-c80-v1-ram.dts','handoff.S','handoff.ld','test-driver.c','driver-test-shim.h','test-mdio.c','mdio-test-shim.h','test-dsa-tag.c','driver-tests/bsp-descriptors.h','flash-reader.inc']:
    assert sha((r/name).read_bytes())==entries[name]['sha256'],name
    checked.append(name)
old=(r/'evidence/ram8-c80_rtl8367s.h').read_text();new=(r/'c80_rtl8367s.h').read_text()
assert sha(old.encode())==entries['c80_rtl8367s.h']['sha256']
expected='''/* ECO4[4:0] differs between measured boots (001f and 0000).
	 * Keep the conservative requirement that all higher bits are zero,
	 * including mode-selection bits5/7. Never rewrite this register. */
	if (mode != 0xc0a0 || (eco & ~0x001fu) ||'''
assert old.replace('if (mode != 0xc0a0 || eco != 0x1f ||',expected,1)==new
k=r/'linux-6.12.113'
assert (k/'drivers/net/dsa/realtek/c80_rtl8367s.h').read_bytes()==new.encode()
for name in ['c80_ram_eth.c','c80_pdma_core.h','c80_ram_mdio.c','c80_ram_mdio.h']:assert(r/name).read_bytes()==(k/'drivers/net/ethernet/mediatek'/name).read_bytes()
assert (r/'rtl8365mb-patched.c').read_bytes()==(k/'drivers/net/dsa/realtek/rtl8365mb.c').read_bytes()
def cfg(p):return [x for x in p.read_text().splitlines() if x.startswith(('CONFIG_','# CONFIG_')) and not x.startswith(('CONFIG_LOCALVERSION=','CONFIG_INITRAMFS_SOURCE='))]
assert cfg(r/'build/.config')==cfg(r/'evidence/ram8-kernel.config')
report=[]
for name,prior in [('c80_rtl8367s.h','ram8-c80_rtl8367s.h'),('init.c','ram8-init.c'),('net-commands.inc','ram8-net-commands.inc')]:
    report.extend(difflib.unified_diff((r/'evidence'/prior).read_text().splitlines(True),(r/name).read_text().splitlines(True),fromfile='RAM8/'+name,tofile='RAM9/'+name))
(r/'artifacts/ram8-to-ram9.diff').write_text(''.join(report))
result={'status':'pass','scope':__doc__,'parent_zip_sha256':'2928678455751ffed82ee0d930f1175c09f1bb4a2ece0e2a3bbab50e58e82c6b','unchanged_files':checked,'kernel_feature_changes':False,'kernel_source_change':'Only ECO guard in c80_rtl8367s.h; no new register writes','eco_accepted_values':'0x0000..0x001f, all higher bits rejected','native_reused':['PDMA15481','MDIO6306'],'native_rerun':['DSA control exhaustive ECO16bit in both up/down states,524656 checks and80 error cases','Linux packet code284 checks'],'userspace_rerun':'73 ARM cases including read-only dmesg and missing-all-netdev regression','hardware_tested_ram9':False}
(r/'artifacts/change-scope-verification.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
