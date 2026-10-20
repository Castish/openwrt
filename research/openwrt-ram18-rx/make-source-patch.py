#!/usr/bin/env python3
"""Generate and apply-check the complete patch against the verified Linux tarball."""
import argparse
import difflib
import hashlib
from pathlib import Path
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--source-archive', type=Path, default=ROOT.parent / 'linux-bringup/downloads/linux-6.12.113.tar.xz')
args = parser.parse_args()
assert hashlib.sha256(args.source_archive.read_bytes()).hexdigest() == 'e09b6727e5c521253f0d41694900b9c38fb7604db7d35238a8197aa9f7de2428'
names = [
    'drivers/power/reset/Kconfig',
    'drivers/power/reset/Makefile',
    'drivers/power/reset/c80-restart.c',
    'drivers/soc/mediatek/Kconfig',
    'drivers/soc/mediatek/Makefile',
    'drivers/soc/mediatek/c80_mcu_transport.c',
    'drivers/soc/mediatek/c80_mcu_core.h',
    'arch/arm/mach-mediatek/mediatek.c',
    'arch/arm/mach-mediatek/Kconfig',
    'arch/arm/boot/dts/mediatek/Makefile',
    'drivers/tty/serial/8250/8250_mtk.c',
    'drivers/net/ethernet/mediatek/Kconfig',
    'drivers/net/ethernet/mediatek/Makefile',
    'drivers/net/dsa/realtek/rtl8365mb.c',
    'arch/arm/boot/dts/mediatek/mt7626-archer-c80-v1-ram.dts',
    'drivers/net/ethernet/mediatek/c80_ram_eth.c',
    'drivers/net/ethernet/mediatek/c80_pdma_core.h',
    'drivers/net/ethernet/mediatek/c80_ram_mdio.c',
    'drivers/net/ethernet/mediatek/c80_ram_mdio.h',
    'drivers/net/dsa/realtek/c80_rtl8367s.h',
]
patch = []
with tarfile.open(args.source_archive, 'r:xz') as archive, tempfile.TemporaryDirectory(prefix='patch-check-', dir=ROOT) as temporary:
    check = Path(temporary)
    for i, name in enumerate(names):
        member = 'linux-6.12.113/' + name
        if member in archive.getnames():
            original = archive.extractfile(member).read()
            target = check / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(original)
        else:
            original = b''
        updated = (ROOT / 'linux-6.12.113' / name).read_bytes()
        assert original != updated, 'Unchanged file in patch: ' + name
        patch.extend(difflib.unified_diff(original.decode().splitlines(True), updated.decode().splitlines(True),
                     fromfile='a/' + name if original else '/dev/null', tofile='b/' + name))
    path = ROOT / 'linux-mt7626-bringup.patch'
    path.write_text(''.join(patch))
    applied = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', str(path)], cwd=check,
                             capture_output=True, text=True, check=True)
    assert not applied.stderr
    assert 'offset' not in applied.stdout and 'fuzz' not in applied.stdout
    for name in names:
        assert (check / name).read_bytes() == (ROOT / 'linux-6.12.113' / name).read_bytes(), name
    report = applied.stdout + 'All twenty files match actual OpenWrt RAM18 RX0 recycling build inputs; no fuzz or offsets.\n'
    (ROOT / 'artifacts/patch-verification.txt').write_text(report)
    print(report, end='')
