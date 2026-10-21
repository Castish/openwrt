#!/usr/bin/env python3
"""Extend a separate RAM1 Linux source copy; never edit issued parent trees."""
from pathlib import Path
import re
root=Path(__file__).resolve().parent
source=root/'linux-6.12.113'
target=source/'drivers/soc/mediatek'
for name in ('c80_mcu_transport.c','c80_mcu_core.h','c80_net_types.h','c80_net_core.h','c80_net_linux.h','c80_net_selftest.c','c80_cfg80211.h','c80_session_core.h'):
    (target/name).write_bytes((root/name).read_bytes())
p=target/'Kconfig';text=p.read_text()
text=re.sub(r'depends on MACH_MT7626 && OF && FW_LOADER && !SMP(?: && CFG80211)*',
            'depends on MACH_MT7626 && OF && FW_LOADER && !SMP && CFG80211',text)
text=text.replace('No 802.11 interface or flash programming support.',
                  'Single open AP via cfg80211; no flash programming support.')
p.write_text(text)
block='''config C80_MCU_TRANSPORT_TEST
\tbool "C80 RAM MCU transport experiment"
\tdepends on MACH_MT7626 && OF && FW_LOADER && !SMP && CFG80211
\thelp
\t  Explicit sysfs MCU transport test with coherent DMA and reserved EMI.
\t  Single open AP via cfg80211; no flash programming support.

'''
if 'config C80_MCU_TRANSPORT_TEST' not in text:
    text=text.replace('endmenu\n',block+'endmenu\n')
    p.write_text(text)
p=target/'Makefile';text=p.read_text()
if 'CONFIG_C80_MCU_TRANSPORT_TEST' not in text:
    p.write_text(text+'obj-$(CONFIG_C80_MCU_TRANSPORT_TEST) += c80_mcu_transport.o\n')
(source/'arch/arm/boot/dts/mediatek/mt7626-archer-c80-v1-ram.dts').write_bytes(
    (root/'mt7626-archer-c80-v1-emi.dts').read_bytes())
print('Separate Linux MCU transport sources/DT prepared.')
target=source/'drivers/power/reset'
(target/'c80-restart.c').write_bytes((root/'c80_restart.c').read_bytes())
p=target/'Kconfig';text=p.read_text()
block='''config POWER_RESET_C80
\tbool "TP-Link Archer C80 MT7626 system restart"
\tdepends on ARCH_MEDIATEK && OF
\thelp
\t  Register a restart callback using the observed factory sequence.
\t  Does not arm a running watchdog timer.

'''
if 'config POWER_RESET_C80' not in text:
    p.write_text(text.replace('endif\n',block+'endif\n'))
p=target/'Makefile';text=p.read_text()
if 'CONFIG_POWER_RESET_C80' not in text:
    p.write_text(text+'obj-$(CONFIG_POWER_RESET_C80) += c80-restart.o\n')

p=source/'drivers/soc/mediatek/Kconfig';text=p.read_text()
if 'config C80_NET_SELFTEST' not in text:
    text=text.replace('endmenu\n', 'config C80_NET_SELFTEST\n\tbool "C80 network software peer (QEMU ONLY)"\n\tdepends on ARCH_VIRT && C80_MCU_TRANSPORT_TEST\n\tdefault n\n\thelp\n\t  Test actual Linux network callbacks without C80 peripherals.\n\t  Never enable in a router image.\n\nendmenu\n')
    p.write_text(text)
p=source/'drivers/soc/mediatek/Makefile';text=p.read_text()
if 'CONFIG_C80_NET_SELFTEST' not in text:p.write_text(text+'obj-$(CONFIG_C80_NET_SELFTEST) += c80_net_selftest.o\n')
