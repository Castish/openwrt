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
for filename in ('c80_ram_eth.c', 'c80_pdma_core.h', 'c80_ram_mdio.c', 'c80_ram_mdio.h'):
    (source / 'drivers/net/ethernet/mediatek' / filename).write_text((root / filename).read_text())
kconfig = source / 'drivers/net/ethernet/mediatek/Kconfig'
text = kconfig.read_text().replace('RAM PDMA polling test', 'RAM PDMA IRQ/NAPI test')
kconfig.write_text(text)
if 'config C80_RAM_ETH\n' not in text:
    text += '\nconfig C80_RAM_ETH\n\tbool "Experimental C80 RAM PDMA IRQ/NAPI test"\n\tdepends on OF && ARCH_MEDIATEK && !SMP\n'
    kconfig.write_text(text)
text = kconfig.read_text()
if '\tselect MDIO_DEVICE\n' not in text:
    text = text.replace('config C80_RAM_ETH\n', 'config C80_RAM_ETH\n\tselect MDIO_DEVICE\n')
    kconfig.write_text(text)
makefile = source / 'drivers/net/ethernet/mediatek/Makefile'
text = makefile.read_text()
text = text.replace('obj-$(CONFIG_C80_RAM_ETH) += c80_ram_eth.o',
                    'obj-$(CONFIG_C80_RAM_ETH) += c80-ram-eth.o\n'
                    'c80-ram-eth-y := c80_ram_eth.o c80_ram_mdio.o')
if 'CONFIG_C80_RAM_ETH' not in text:
    text += '\nobj-$(CONFIG_C80_RAM_ETH) += c80-ram-eth.o\nc80-ram-eth-y := c80_ram_eth.o c80_ram_mdio.o\n'
makefile.write_text(text)

# The complete ram5 patch is regenerated against pristine signed source by packaging.
print('Experimental kernel changes prepared.')
