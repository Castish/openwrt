#!/usr/bin/env python3
"""Apply small, reviewable experimental changes to verified Linux 6.12.113."""
from pathlib import Path
import difflib

root = Path(__file__).resolve().parent
source = root / 'linux-6.12.113'
changes = {
    'arch/arm/mach-mediatek/mediatek.c': (
        '\t"mediatek,mt7623",\n', '\t"mediatek,mt7623",\n\t"mediatek,mt7626",\n'),
    'arch/arm/mach-mediatek/Kconfig': (
        'config MACH_MT7629\n',
        'config MACH_MT7626\n\tbool "Experimental MediaTek MT7626 RAM bring-up"\n'
        '\tselect HAVE_ARM_ARCH_TIMER\n\nconfig MACH_MT7629\n'),
    'arch/arm/boot/dts/mediatek/Makefile': (
        'dtb-$(CONFIG_ARCH_MEDIATEK) += \\\n',
        'dtb-$(CONFIG_MACH_MT7626) += mt7626-archer-c80-v1-ram.dtb\n'
        'dtb-$(CONFIG_ARCH_MEDIATEK) += \\\n'),
    'drivers/tty/serial/8250/8250_mtk.c': (
        '\tirq = platform_get_irq(pdev, 0);\n\tif (irq < 0)\n\t\treturn irq;\n',
        '\t/* Experimental C80 bring-up: use 8250 timer polling until IRQ is verified. */\n'
        '\tif (of_property_read_bool(pdev->dev.of_node, "tplink,bringup-polling"))\n'
        '\t\tirq = 0;\n\telse {\n\t\tirq = platform_get_irq(pdev, 0);\n'
        '\t\tif (irq < 0)\n\t\t\treturn irq;\n\t}\n'),
}
patch = []
for name, (before, after) in changes.items():
    path = source / name
    original = path.read_text()
    if after in original:
        continue
    if original.count(before) != 1:
        raise RuntimeError(f'Unexpected source anchor: {name}')
    updated = original.replace(before, after, 1)
    patch.extend(difflib.unified_diff(original.splitlines(True), updated.splitlines(True),
                                      fromfile='a/' + name, tofile='b/' + name))
    path.write_text(updated)
dt_name = 'arch/arm/boot/dts/mediatek/mt7626-archer-c80-v1-ram.dts'
dt_data = (root / 'mt7626-archer-c80-v1-ram.dts').read_text()
dt_path = source / dt_name
if not dt_path.exists():
    patch.extend(difflib.unified_diff([], dt_data.splitlines(True),
                                      fromfile='/dev/null', tofile='b/' + dt_name))
dt_path.write_text(dt_data)
if patch:
    (root / 'linux-mt7626-bringup.patch').write_text(''.join(patch))
print('Experimental kernel changes prepared.')
