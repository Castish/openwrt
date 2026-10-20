#!/usr/bin/env python3
"""Boot the exact C80 rootfs on QEMU virt with a separate verification kernel.

This checks OpenWrt init/procd/IPC/network userspace, not MT7626 hardware.
The QEMU kernel differs only in the platform/console/virtual NIC options.
"""
from pathlib import Path
import hashlib
import json
import os
import re
import selectors
import subprocess
import time

base = Path(__file__).resolve().parent
evidence = base / 'evidence'
rawlog = (evidence / 'qemu-openwrt-boot.log').open('wb')
process = subprocess.Popen(['bash', str(base / 'run-qemu-check.sh')],
                           stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, bufsize=0)
selector = selectors.DefaultSelector()
selector.register(process.stdout, selectors.EVENT_READ)
pending = bytearray()
all_output = bytearray()
results = []
prompt = re.compile(rb'root@[^\r\n ]+:[^\r\n]*# ')

def receive_until(marker, timeout=30):
    deadline = time.monotonic() + timeout
    def locate():
        if isinstance(marker, re.Pattern):
            match = marker.search(pending)
            return match.end() if match else None
        return pending.index(marker) + len(marker) if marker in pending else None
    while locate() is None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f'QEMU output did not reach {marker!r}')
        for key, mask in selector.select(min(remaining, 0.25)):
            data = os.read(key.fileobj.fileno(), 65536)
            if not data:
                raise RuntimeError(f'QEMU exited early ({process.poll()})')
            rawlog.write(data)
            rawlog.flush()
            pending.extend(data)
            all_output.extend(data)
    end = locate()
    data = bytes(pending[:end])
    del pending[:end]
    return data.decode(errors='replace').replace('\r', '')

def send(command):
    # Give ash time to configure the TTY after drawing the prompt, then pace
    # input through the emulated UART instead of flooding its tiny FIFO.
    time.sleep(0.05)
    for byte in command.encode() + b'\n':
        process.stdin.write(bytes([byte]))
        process.stdin.flush()
        time.sleep(0.001)

def command(name, text, expected=None):
    number = len(results)
    marker = f'C80_STATUS_{number}='
    send(text + "; printf '\\n" + marker + "%d\\n' \"$?\"")
    output = receive_until(prompt, timeout=30)
    match = re.search(r'^' + re.escape(marker) + r'(\d+)$', output, re.M)
    assert match and match[1] == '0', (name, output)
    if expected:
        assert expected in output, (name, output)
    results.append({'name': name, 'command': text, 'exit_status': 0, 'output': output})
    return output

try:
    receive_until(b'Please press Enter to activate this console.', timeout=45)
    send('')
    receive_until(prompt)
    command('wait-for-network-service', 'ubus -t 20 wait_for network')
    command('release', 'cat /etc/openwrt_release', "DISTRIB_RELEASE='25.12.5'")
    command('pid1', 'cat /proc/1/comm', '\nprocd\n')
    command('ubus', 'ubus list', '\nnetwork\n')
    command('system-board', 'ubus call system board', 'OpenWrt')
    command('network-service', '''ubus call service list '{"name":"network"}' ''', '"running": true')
    command('virtual-nic-down', 'ip link set dev eth0 down')
    command('virtual-nic-rename', 'ip link set dev eth0 name lan1')
    command('network-reload', 'ubus call network reload')
    command('wait-for-lan-interface', 'ubus -t 20 wait_for network.interface.lan')
    deadline = time.monotonic() + 12
    while True:
        output = command('lan-status', 'ubus call network.interface.lan status')
        if '"up": true' in output and '192.168.0.1' in output:
            break
        assert time.monotonic() < deadline, output
    command('lan-address', 'ip -4 address show dev lan1', '192.168.0.1/24')
    command('virtual-network-ping', 'ping -c 3 -W 2 192.168.0.3', '0% packet loss')
    command('logger', 'logger C80_OPENWRT_SMOKE_OK')
    command('logread', 'logread -e C80_OPENWRT_SMOKE_OK', 'C80_OPENWRT_SMOKE_OK')
    command('legacy-time-api', 'cp -p /etc/openwrt_release /tmp/c80-release-copy')
    command('uci-write', 'uci set system.@system[0].hostname=ram-only-test')
    command('uci-commit', 'uci commit system')
    command('uci-readback', 'uci get system.@system[0].hostname', '\nram-only-test\n')
    memory = command('memory', 'cat /proc/meminfo', 'MemAvailable:')
    available = int(re.search(r'MemAvailable:\s+(\d+)', memory)[1])
    assert available > 4096, available
    command('mounts', 'cat /proc/mounts', 'tmpfs / tmpfs')
    command('processes', 'ps w', '/sbin/netifd')
    assert b"can't preserve times" not in all_output
    assert b'Kernel panic' not in all_output
    assert b'Out of memory' not in all_output
    send('poweroff -f')
    process.wait(timeout=10)
    assert process.returncode == 0
    report = {
        'scope': __doc__, 'passed': True, 'ram_bytes': 32 * 1024 * 1024,
        'mem_available_kib_after_services': available,
        'rootfs_cpio_sha256': hashlib.sha256((base / 'build/usr/initramfs_data.cpio').read_bytes()).hexdigest(),
        'qemu_kernel_sha256': hashlib.sha256((base / 'build-qemu/arch/arm/boot/zImage').read_bytes()).hexdigest(),
        'commands': results,
        'does_not_emulate_c80_hardware': True,
    }
    # Check that both kernels embed byte-identical userspace.
    assert (base / 'build/usr/initramfs_data.cpio').read_bytes() == (base / 'build-qemu/usr/initramfs_data.cpio').read_bytes()
    (evidence / 'qemu-openwrt-result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f'OpenWrt QEMU boot passed: {len(results)} command checks, {available} KiB available with 32 MiB RAM.')
finally:
    if process.poll() is None:
        process.terminate()
        process.wait(timeout=5)
    rawlog.close()
