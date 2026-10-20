#!/usr/bin/env python3
"""Boot the exact C80 rootfs on QEMU virt with a separate verification kernel.

This checks OpenWrt init/procd/IPC/network userspace, not MT7626 hardware.
The QEMU kernel differs only in the platform/console/virtual NIC options.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import selectors
import subprocess
import time

mode='linux-network'
base = Path(__file__).resolve().parent
parent = base
evidence = base / 'evidence'
rawlog = (evidence / f'qemu-{mode}-boot.log').open('wb')
process = subprocess.Popen(['bash', str(base / 'run-qemu-emi-check.sh')],
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
    time.sleep(0.25)
    for byte in command.encode() + b'\n':
        process.stdin.write(bytes([byte]))
        process.stdin.flush()
        time.sleep(0.005)

def command(name, text, expected=None):
    number = len(results)
    marker = f'C80_STATUS_{number}='
    send(text + "; printf '\\n" + marker + "%d\\n' \"$?\"")
    output = receive_until(prompt, timeout=60)
    match = re.search(r'^' + re.escape(marker) + r'(\d+)$', output, re.M)
    assert match and match[1] == '0', (name, output)
    if expected:
        assert expected in output, (name, output)
    results.append({'name': name, 'command': text, 'exit_status': 0, 'output': output})
    return output

try:
    receive_until(b'Please press Enter to activate this console.',timeout=60)
    send('');receive_until(prompt);send('');receive_until(prompt)
    command('wait-network','ubus -t 20 wait_for network')
    command('QEMU-only-device','test -w /sys/kernel/c80_net_selftest/inject')
    command('helper-help','if c80-wifi bad; then false; else true; fi','Usage: c80-wifi')
    command('helper-QEMU-kernel-guard','if c80-wifi start; then false; else true; fi','requires the RAM28 netdev router kernel')
    command('helper-no-start-side-effect','test ! -d /tmp/c80-wifi-once')
    command('helper-status','c80-wifi status','Not started.')
    command('wait-wifi-interface','ubus -t 20 wait_for network.interface.wifi_ram')
    deadline=time.monotonic()+20
    while True:
        st=command('wifi-netifd-status','ubus call network.interface.wifi_ram status')
        if '"up": true' in st and '192.168.2.1' in st:break
        assert time.monotonic()<deadline,st
    command('Linux-device-MTU','cat /sys/class/net/c80wlan0/mtu','1400')
    command('Linux-device-carrier','cat /sys/class/net/c80wlan0/carrier','1')
    command('MTU-boundary','if ifconfig c80wlan0 mtu 1500; then false; else true; fi')
    command('MTU-preserved','cat /sys/class/net/c80wlan0/mtu','1400')
    deadline=time.monotonic()+20
    while True:
        st=command('dnsmasq-service',"ubus call service list '{\"name\":\"dnsmasq\"}'")
        if '"running": true' in st:break
        assert time.monotonic()<deadline,st
    deadline=time.monotonic()+20
    while True:
        st=command('dropbear-service',"ubus call service list '{\"name\":\"dropbear\"}'")
        if '"running": true' in st:break
        assert time.monotonic()<deadline,st
    result=command('actual-kernel-and-userspace-peer','/usr/sbin/c80-net-selftest','PASS LINUX-NETWORK 13')
    assert 'FAIL' not in result
    leases=command('DHCP-lease','cat /tmp/dhcp.leases','192.168.2.2')
    assert '02:c0:80:28:00:02' in leases
    counters=command('actual-netdev-counters','cat /proc/net/dev','c80wlan0:')
    match=re.search(r'c80wlan0:\s+(\d+)\s+(\d+)',counters)
    assert match and int(match[2])>=13,counters
    command('MCU-still-inactive','cat /sys/kernel/c80_wifi/status','ran=0 finished=0')
    memory=command('memory','cat /proc/meminfo','MemAvailable:')
    available=int(re.search(r'MemAvailable:\s+(\d+)',memory)[1]);assert available>4096
    command('rootfs-RAM-only','cat /proc/mounts','tmpfs / tmpfs')
    assert b'Kernel panic' not in all_output and b'Out of memory' not in all_output
    send('poweroff -f');process.wait(timeout=10);assert process.returncode==0
    sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
    report={'passed':True,'commands':results,'protocol_checks':13,'actual_Linux_network_callbacks':True,'actual_OpenWrt_netifd_dnsmasq_dropbear':True,'C80_MCU_RF_DMA_emulated':False,'physical_tested':False,'memory_available_KiB':available,'qemu_kernel_sha256':sha(base/'build-qemu/arch/arm/boot/zImage'),'qemu_CPIO_sha256':sha(base/'build-qemu/usr/initramfs_data.cpio'),'Linux_callbacks_source_sha256':sha(base/'c80_net_linux.h'),'test_peer_driver_sha256':sha(base/'c80_net_selftest.c'),'ARM_userspace_peer_source_sha256':sha(base/'verify-linux-network.c'),'ARM_userspace_peer_binary_sha256':sha(base/'artifacts/c80-net-selftest'),'mode':'QEMU-only synthetic Ethernet peer; actual Linux stack/services, no C80 peripherals'}
    (evidence/'qemu-linux-network-result.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS QEMU Linux network:13 real kernel/service protocol checks, '+str(len(results))+' command checks, '+str(available)+'KiB available')
finally:
    if process.poll() is None:process.terminate();process.wait(timeout=5)
    rawlog.close()
