#!/usr/bin/env python3
"""Check actual kernel/DTB/initramfs outputs, configuration and RAM placement."""
from pathlib import Path
import gzip
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess

ROOT = Path(__file__).resolve().parent
BUILD = ROOT / 'build'
ART = ROOT / 'artifacts'
ART.mkdir(exist_ok=True)
kernel = (BUILD / 'arch/arm/boot/zImage').read_bytes()
dtb = (BUILD / 'arch/arm/boot/dts/mediatek/mt7626-archer-c80-v1-ram.dtb').read_bytes()
init = (ROOT / 'rootfs/init').read_bytes()
assert struct.unpack_from('<I', kernel, 0x24)[0] == 0x016F2818
assert struct.unpack_from('<I', kernel, 0x2C)[0] == len(kernel)

# Validate the compiled DTB, not just its source.
magic, total, off_struct, off_strings, off_reserve, version, last, bootcpu, str_size, struct_size = struct.unpack_from('>10I', dtb)
assert magic == 0xD00DFEED and total == len(dtb)
strings = dtb[off_strings:off_strings + str_size]
props = {}
nodes = []
stack = []
pos = off_struct
while True:
    token = struct.unpack_from('>I', dtb, pos)[0]
    pos += 4
    if token == 1:
        end = dtb.index(0, pos)
        stack.append(dtb[pos:end].decode())
        pos = (end + 4) & ~3
        nodes.append('/' + '/'.join(stack[1:]))
    elif token == 2:
        stack.pop()
    elif token == 3:
        size, nameoff = struct.unpack_from('>2I', dtb, pos)
        pos += 8
        name = strings[nameoff:strings.index(0, nameoff)].decode()
        props[('/' + '/'.join(stack[1:]), name)] = dtb[pos:pos + size]
        pos = (pos + size + 3) & ~3
    elif token == 4:
        pass
    elif token == 9:
        break
    else:
        raise AssertionError(('Invalid DT token', token))
assert props[('/chosen','linux,usable-memory-range')]==struct.pack('>2I',0x40200000,0x1e00000)
assert props[('/reserved-memory/memory@40000000','reg')]==struct.pack('>2I',0x40000000,0x200000)
assert ('/reserved-memory/memory@40000000','no-map') in props
assert props[('/soc/restart-controller@10212000','reg')]==struct.pack('>2I',0x10212000,0x18)
wifi='/soc/wifi-test@18000000'
assert props[(wifi,'compatible')]==b'tplink,c80-mcu-transport-test\0'
assert props[(wifi,'reg')]==struct.pack('>10I',0x18000000,0x100000,0x10000000,0x1000,0x10006000,0x1000,0x10212018,4,0x10210000,0x1000)
assert props[(wifi,'memory-region')]==props[('/reserved-memory/memory@40000000','phandle')]
assert props[(wifi,'interrupts')]==struct.pack('>3I',0,211,8)
assert props[(wifi,'interrupt-parent')]==props[('/soc/interrupt-controller@10200a80','phandle')]
assert (wifi,'dma-coherent') not in props
assert props[('/', 'compatible')].split(b'\0')[:2] == [b'tplink,archer-c80-v1', b'mediatek,mt7626']
assert struct.unpack('>2I', props[('/memory@40000000', 'reg')]) == (0x40000000, 0x02000000)
assert [n for n in nodes if n.startswith('/cpus/cpu@')] == ['/cpus/cpu@0']
assert struct.unpack('>4I', props[('/soc/interrupt-controller@10310000', 'reg')]) == (0x10310000, 0x1000, 0x10320000, 0x1000)
assert ('/soc/serial@11002000', 'tplink,bringup-polling') in props
assert ('/soc/serial@11002000', 'interrupts') not in props
assert struct.unpack('>I', props[('/timer', 'clock-frequency')])[0] == 20_000_000
assert struct.unpack('>I', props[('/uart-clock', 'clock-frequency')])[0] == 40_000_000

# Verify the entire OpenWrt initramfs, including symlinks, devices, and root ownership.
cpio = (BUILD / 'usr/initramfs_data.cpio').read_bytes()
packed = (BUILD / 'usr/initramfs_inc_data').read_bytes()
assert gzip.decompress(packed) == cpio
entries = {}
pos = 0
while True:
    assert cpio[pos:pos + 6] == b'070701'
    fields = [int(cpio[pos + 6 + n * 8:pos + 14 + n * 8], 16) for n in range(13)]
    namesize, filesize = fields[11], fields[6]
    name = cpio[pos + 110:pos + 110 + namesize - 1].decode()
    start = (pos + 110 + namesize + 3) & ~3
    content = cpio[start:start + filesize]
    pos = (start + filesize + 3) & ~3
    if name == 'TRAILER!!!':
        break
    entries[name.lstrip('/')] = (fields, content)
assert entries['init'][1] == init
assert b'export INITRAMFS=1' in init and b'exec switch_root' in init
for path in (ROOT / 'rootfs').rglob('*'):
    name = str(path.relative_to(ROOT / 'rootfs'))
    assert name in entries, name
    fields, content = entries[name]
    assert fields[2:4] == [0, 0], name
    if path.is_symlink():
        assert content.rstrip(b'\0') == os.readlink(path).encode(), name
    elif path.is_file():
        assert content == path.read_bytes(), name
assert b'192.168.0.1' in entries['etc/config/network'][1]
assert b"option device 'lan1'" in entries['etc/config/network'][1]
assert b"DISTRIB_RELEASE='25.12.5'" in entries['etc/openwrt_release'][1]
assert b"DISTRIB_TARGET='mediatek/mt7626-c80-ram'" in entries['etc/openwrt_release'][1]
assert 'etc/rc.d/S19dropbear' not in entries
assert 'lib/preinit/01_c80_ram.conf' in entries
assert 'lib/preinit/00_c80_ram.conf' not in entries
for name in ('init', 'etc/preinit', 'sbin/init', 'sbin/procd', 'sbin/netifd',
             'sbin/uci', 'sbin/ubusd', 'bin/ubus', 'bin/busybox', 'sbin/logd'):
    assert name in entries and entries[name][1], name

assert entries['init'][0][1] & 0o111 and entries['init'][0][2:4] == [0, 0]
assert entries['dev/console'][0][1] & 0o170000 == 0o020000
assert entries['dev/console'][0][9:11] == [5, 1]
assert {'dev', 'proc', 'sys', 'tmp', 'dev/null'} <= set(entries)

assert props[('/soc/flash@30000000', 'compatible')] == b'mtd-rom\0'
assert struct.unpack('>2I', props[('/soc/flash@30000000', 'reg')]) == (0x30000000, 0x400000)
assert struct.unpack('>I', props[('/soc/flash@30000000', 'bank-width')])[0] == 1
assert b'keep_bootcon' not in props[('/chosen', 'bootargs')]
assert props[('/soc/ethernet@1b100000', 'compatible')] == b'tplink,c80-ram-pdma\0'
assert struct.unpack('>6I', props[('/soc/ethernet@1b100000', 'reg')]) == (0x1b100000, 0x20000, 0x1b128000, 0x200, 0x1b000000, 0x1000)
assert struct.unpack('>3I', props[('/soc/ethernet@1b100000', 'interrupts')]) == (0, 223, 8)
assert struct.unpack('>2I', props[('/soc/interrupt-controller@10200a80', 'reg')]) == (0x10200a80, 0x20)
assert props[('/soc/interrupt-controller@10200a80', 'compatible')].split(b'\0')[:2] == [b'mediatek,mt7626-sysirq', b'mediatek,mt6577-sysirq']
assert props[('/soc/ethernet@1b100000', 'interrupt-parent')] == props[('/soc/interrupt-controller@10200a80', 'phandle')]
assert props[('/soc/interrupt-controller@10200a80', 'interrupt-parent')] == props[('/soc/interrupt-controller@10310000', 'phandle')]
eth='/soc/ethernet@1b100000'
sw=eth+'/mdio/switch@1d'
assert (eth,'tplink,dsa-conduit') in props
assert props[(sw,'compatible')]==b'realtek,rtl8365mb\0'
assert props[(sw,'reg')]==struct.pack('>I',29)
assert (sw,'tplink,c80-ram-inherit-hsgmii') in props
for port,label in ((0,'wan'),(1,'lan1'),(2,'lan2'),(3,'lan3'),(4,'lan4')):
    node=sw+'/ports/port@'+str(port);phy=sw+'/mdio/ethernet-phy@'+str(port)
    assert props[(node,'reg')]==struct.pack('>I',port)
    assert props[(node,'label')]==label.encode()+b'\0'
    assert props[(node,'phy-mode')]==b'internal\0'
    assert props[(node,'phy-handle')]==props[(phy,'phandle')]
    assert props[(phy,'reg')]==struct.pack('>I',port)
cpu=sw+'/ports/port@6'
assert props[(cpu,'reg')]==struct.pack('>I',6)
assert props[(cpu,'ethernet')]==props[(eth,'phandle')]
assert props[(cpu,'phy-mode')]==b'2500base-x\0'
assert props[(cpu+'/fixed-link','speed')]==struct.pack('>I',2500)
assert (cpu+'/fixed-link','full-duplex') in props
assert (cpu+'/fixed-link','pause') not in props and (cpu+'/fixed-link','asym-pause') not in props
assert len([n for n in nodes if n.startswith(sw+'/ports/port@') and '/' not in n[len(sw+'/ports/'):]])==6
assert not any('reset' in key or 'gpio' in key for (node,key) in props if node.startswith(sw))
assert (ROOT/'linux-6.12.113/drivers/soc/mediatek/c80_mcu_core.h').read_bytes()==(ROOT/'c80_mcu_core.h').read_bytes()
assert (ROOT/'linux-6.12.113/drivers/soc/mediatek/c80_mcu_transport.c').read_bytes()==(ROOT/'c80_mcu_transport.c').read_bytes()
assert 'drivers/soc/mediatek/c80_mcu_transport.o' in (ROOT/'build.log').read_text()
config = (BUILD / '.config').read_text()
for name in ('BINFMT_SCRIPT', 'FUTEX', 'EPOLL', 'EVENTFD', 'SIGNALFD', 'TIMERFD',
             'COMPAT_32BIT_TIME', 'UNIX', 'PACKET', 'UNIX98_PTYS', 'CGROUPS',
             'SECCOMP', 'SECCOMP_FILTER', 'ARCH_KEEP_MEMBLOCK', 'OF_RESERVED_MEM', 'FW_LOADER', 'C80_MCU_TRANSPORT_TEST', 'POWER_RESET_C80',
             'MMU', 'ARCH_MULTI_V7', 'MACH_MT7626', 'ARM_ARCH_TIMER', 'PRINTK',
             'SERIAL_8250_MT6577', 'SERIAL_8250_CONSOLE', 'ARM_PATCH_PHYS_VIRT',
             'ARM_ERRATA_814220', 'MTD', 'MTD_ROM', 'MTD_PHYSMAP', 'MTD_PHYSMAP_OF', 'NET', 'INET', 'NETDEVICES', 'C80_RAM_ETH', 'MDIO_DEVICE', 'MDIO_BUS', 'PHYLIB', 'NET_DSA', 'NET_DSA_REALTEK_MDIO', 'NET_DSA_REALTEK_RTL8365MB', 'NET_DSA_TAG_RTL8_4'):
    assert f'CONFIG_{name}=y\n' in config, name
for name in ('MTD_CFI', 'MTD_JEDECPROBE', 'MTD_SPI_NOR', 'MTD_RAM', 'SPI', 'NET_MEDIATEK_SOC', 'IPV6', 'WLAN', 'SMP', 'HIGHMEM', 'ARM_LPAE', 'GPIOLIB'):
    assert f'CONFIG_{name}=y\n' not in config, name
env = dict(os.environ)
env['LD_LIBRARY_PATH'] = str(ROOT.parent / 'linux-bringup/tools/usr/lib/x86_64-linux-gnu') + ':' + env.get('LD_LIBRARY_PATH', '')
cross = os.environ.get('CROSS_COMPILE', str(ROOT.parent / 'linux-bringup/tools/usr/bin/arm-linux-gnueabi-'))
symbols = subprocess.check_output([cross + 'nm', '-n', str(BUILD / 'vmlinux')], env=env, text=True)
for name in ('c80_restart', 'c80_restart_probe', 'c80_mcu_probe', 'c80_linux_nvm_read', 'c80_mcu_irq', 'c80_linux_irq_arm', 'c80_linux_irq_disarm', 'run_store', 'status_show', 'memblock_is_map_memory', 'dma_alloc_attrs', 'c80_irq', 'c80_poll', 'c80_probe', 'mtk_sysirq_set_type', 'mtk_sysirq_of_init',
             'c80_mdio_register', 'c80_mdio_snapshot', 'c80_mdio_read', 'c80_mdio_write',
             'c80_mdio_link_test', 'c80_mdio_link_state', 'c80_mdio_ready',
             '__mdiobus_register', '__mdiobus_read', '__mdiobus_write',
             'rtl8365mb_detect', 'rtl8365mb_setup', 'rtl8365mb_c80_force',
             'rtl8_4_tag_xmit', 'rtl8_4_tag_rcv', 'dsa_user_create', 'phy_init',
             'sys_syslog', 'sys_utimensat_time32'):
    assert re.search(r'^[0-9a-f]+ [tT] ' + name + r'(?:\.\w+)?$', symbols, re.M), name
# PHYLIB initializes the MDIO core at subsys_initcall. Tag registration is a
# device_initcall after this platform; DSA returns EPROBE_DEFER until the conduit
# and tagger are ready. Deferred probes run again after initcall completion.
mdio_initcall = int(re.search(r'^([0-9a-f]+) [a-zA-Z] __initcall.*_phy_init4$', symbols, re.M)[1], 16)
driver_initcall = int(re.search(r'^([0-9a-f]+) [a-zA-Z] __initcall.*_c80_driver_init6$', symbols, re.M)[1], 16)
tagger_initcall = int(re.search(r'^([0-9a-f]+) [a-zA-Z] __initcall.*_dsa_tag_driver_module_init6$', symbols, re.M)[1],16)
assert mdio_initcall < driver_initcall < tagger_initcall
match = re.search(r'^([0-9a-f]+) B _end$', symbols, re.M)
assert match
kernel_runtime_end = int(match[1], 16) - 0xC0000000 + 0x40200000
assert kernel_runtime_end < 0x40E00000
assert 0x41000000 + len(kernel) < 0x41C00000
assert 0x40F00000 + len(dtb) < 0x41000000
qemu_result = json.loads((ROOT / 'evidence/qemu-missing-firmware-result.json').read_text())
assert qemu_result['passed']
assert qemu_result['rootfs_cpio_sha256'] == hashlib.sha256(cpio).hexdigest()
assert (ROOT / 'build-qemu/usr/initramfs_data.cpio').read_bytes() == cpio

shutil.copyfile(ROOT/'c80-openwrt-ram26-handoff.bin',ART/'c80-openwrt-ram26-handoff.bin')
for source, name in [(BUILD / 'arch/arm/boot/zImage', 'c80-openwrt-ram26-echo-zImage'),
                     (BUILD / 'arch/arm/boot/dts/mediatek/mt7626-archer-c80-v1-ram.dtb', 'c80-openwrt-ram26-echo.dtb'),
                     (BUILD / '.config', 'kernel.config')]:
    shutil.copyfile(source, ART / name)
files = ['c80-openwrt-ram26-echo-zImage', 'c80-openwrt-ram26-echo.dtb', 'c80-openwrt-ram26-handoff.bin']
records = [{'file': name, 'bytes': (ART / name).stat().st_size,
            'sha256': hashlib.sha256((ART / name).read_bytes()).hexdigest()}
           for name in files]
(ART / 'SHA256SUMS').write_text(''.join(r['sha256'] + '  ' + r['file'] + '\n' for r in records))
result = {'kernel_version': '6.12.113-c80-openwrt-ram26-echo', 'artifacts': records,
          'kernel_runtime_end_physical': hex(kernel_runtime_end), 'EMI_reserved_no_map':['0x40000000','0x401fffff'], 'MCU_transport_hardware_tested':False,
          'memory_bytes_configured': 0x01e00000, 'physical_ram_capacity_measured': False,
          'dtb_structure_and_hardware_addresses_verified': True,
          'initramfs_entries': sorted(entries), 'initramfs_matches_entire_rootfs': True,
          'kernel_boot_on_hardware': 'RAM26 bounded ARP/ICMP physically pending; parent RAM25 STA create/delete, association header/token and raw data/null candidates passed; Ethernet/restart unchanged',
          'mdio_bus': 'Measured MDIO controller, explicit switch@1d and five PHY nodes, PHYLIB/DSA enabled, GPIO disabled',
          'mdio_core_initcall_precedes_platform_driver': {
              'verified': True, 'core': hex(mdio_initcall), 'platform': hex(driver_initcall), 'tagger':hex(tagger_initcall), 'switch_probe_may_defer':True},
          'port_map': {'wan':0,'lan1':1,'lan2':2,'lan3':3,'lan4':4,'cpu':6},
          'cpu_link':'inherited HSGMII, fixed2500base-x/full-duplex/no-pause, warm-only',
          'kernel_log':'Stock OpenWrt BusyBox dmesg and logd/logread',
          'userspace_release': 'OpenWrt 25.12.5, r33051-f5dae5ece4, arm_cortex-a7 musl EABI soft-float',
          'emulation_scope': 'Handoff tested separately. OpenWrt userspace boot tested on QEMU virt using a separate kernel; no C80 hardware emulation.'}
(ART / 'artifact-verification.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
