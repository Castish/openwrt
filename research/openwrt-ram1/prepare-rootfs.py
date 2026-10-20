#!/usr/bin/env python3
"""Finalize official OpenWrt packages for the C80 RAM-only first boot."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import tarfile

base = Path(__file__).resolve().parent
root = base / 'rootfs'
db = root / 'lib/apk/db'

# Same offline postinstall mechanism used by ImageBuilder include/rootfs.mk.
with tarfile.open(db / 'scripts.tar.gz') as archive:
    for member in archive.getmembers():
        if member.name.endswith('.post-install'):
            assert member.isfile() and '/' not in member.name and '..' not in member.name
            (db / member.name).write_bytes(archive.extractfile(member).read())
(root / 'etc/rc.d').mkdir(exist_ok=True)
(root / 'tmp/lock').mkdir(exist_ok=True)
env = dict(os.environ, IPKG_INSTROOT=str(root))
with (base / 'postinstall.log').open('w') as log:
    for script in sorted(db.glob('*.post-install')):
        subprocess.run(['/bin/bash', str(script)], env=env,
                       stdout=log, stderr=subprocess.STDOUT, check=True)
        script.unlink()

changes = {}
def put(name, content, mode=0o644):
    path = root / name
    assert not path.is_symlink(), name
    before = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    path.chmod(mode)
    changes[name] = {'before_sha256': before,
                     'after_sha256': hashlib.sha256(path.read_bytes()).hexdigest()}

# Use the stock OpenWrt initramfs entry and its INITRAMFS=1/mount_root bypass.
put('init', (base / 'downloads/openwrt-init').read_text(), 0o755)
put('etc/config/network', '''config interface 'loopback'
        option device 'lo'
        option proto 'static'
        option ipaddr '127.0.0.1'
        option netmask '255.0.0.0'

config globals 'globals'
        option packet_steering '0'

config interface 'lan'
        option device 'lan1'
        option proto 'static'
        option ipaddr '192.168.0.1'
        option netmask '255.255.255.0'
''')
put('etc/config/system', '''config system
        option hostname 'c80-openwrt'
        option timezone 'MSK-3'
        option zonename 'Europe/Moscow'
        option ttylogin '0'
        option log_size '64'
        option urandom_seed '0'
''')
put('etc/board.json', json.dumps({
    'model': {'id': 'tplink,archer-c80-v1', 'name': 'TP-Link Archer C80 v1 RU (RAM)'},
    'network': {'lan': {'device': 'lan1', 'protocol': 'static'}},
}, indent=2) + '\n')

# Replace donor-target board hooks; no other router's port layout or flash API.
for path in (root / 'etc/board.d').iterdir():
    if path.is_file() or path.is_symlink():
        changes[str(path.relative_to(root))] = {'removed': True}
        path.unlink()
put('etc/board.d/02_network', '''#!/bin/sh
. /lib/functions/uci-defaults.sh
board_config_update
ucidef_set_interface_lan 'lan1'
board_config_flush
exit 0
''', 0o755)
put('lib/upgrade/platform.sh', '''# C80 experimental RAM userspace: no flash image format is supported.
platform_check_image() {
        echo 'This C80 image supports RAM boot only; sysupgrade is unavailable.' >&2
        return 1
}
platform_do_upgrade() { return 1; }
''')
put('lib/preinit/01_c80_ram.conf', '''# Keep the known management subnet during preinit, too.
pi_ip="192.168.0.1"
pi_broadcast="192.168.0.255"
pi_ifname="lan1"
''')
obsolete_preinit = root / 'lib/preinit/00_c80_ram.conf'
if obsolete_preinit.exists():
    obsolete_preinit.unlink()
release = (root / 'etc/openwrt_release').read_text()
put('etc/openwrt_release', release.replace(
    "DISTRIB_TARGET='mediatek/mt7629'", "DISTRIB_TARGET='mediatek/mt7626-c80-ram'"))
release = (root / 'usr/lib/os-release').read_text()
put('usr/lib/os-release', release.replace(
    'OPENWRT_BOARD="mediatek/mt7629"', 'OPENWRT_BOARD="mediatek/mt7626-c80-ram"').replace(
    'OPENWRT_DEVICE_MANUFACTURER="OpenWrt"', 'OPENWRT_DEVICE_MANUFACTURER="TP-Link"').replace(
    'OPENWRT_DEVICE_PRODUCT="Generic"', 'OPENWRT_DEVICE_PRODUCT="Archer C80 v1 RU RAM"'))
put('etc/c80-ram-release', '''OpenWrt 25.12.5 userspace / custom Linux 6.12.113 C80 RAM kernel
U-Boot-initialized Ethernet/SerDes are still required.
NOR is exposed only by mtd-rom; no writable flash controller is compiled.
Configuration and password changes are volatile.
Management: LAN1, 192.168.0.1/24. No Wi-Fi, DHCP server, NAT or LuCI yet.
''')
put('root/README.txt', '''First C80 OpenWrt RAM boot

Useful commands:
  cat /etc/openwrt_release
  ubus call system board
  ubus call network.interface.lan status
  ip address show dev lan1
  logread
  dmesg

UART provides the root shell. SSH is initially disabled. To test it:
  passwd
  /etc/init.d/dropbear start

All changes are held in RAM and disappear on power loss. Leave the computer
on LAN1 at 192.168.0.3/24. Do not use sysupgrade with this experimental image.
''')

# Keep first boot focused on init, logging, entropy, and LAN1 management.
enabled = {'sysfixtime', 'urngd', 'boot', 'system', 'sysctl', 'log', 'network', 'done', 'umount'}
for path in (root / 'etc/rc.d').iterdir():
    if path.is_symlink() and Path(os.readlink(path)).name not in enabled:
        path.unlink()

# Postinsts have already run offline. Keep no pending install scripts.
with tarfile.open(db / 'scripts.tar.gz', 'w:gz'):
    pass
for path in (root / 'tmp').iterdir():
    if path.is_file() or path.is_symlink():
        path.unlink()
(base / 'rootfs-overrides.json').write_text(json.dumps(changes, indent=2) + '\n')
print('C80 RAM rootfs finalized; normal OpenWrt init/procd/ubus/uci/netifd included.')
