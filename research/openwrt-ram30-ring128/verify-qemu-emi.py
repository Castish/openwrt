#!/usr/bin/env python3
"""Boot the exact C80 rootfs on QEMU virt with a separate verification kernel.

This checks OpenWrt init/procd/IPC/network userspace, not MT7626 hardware.
The QEMU kernel adds platform/console/virtual NIC options and an isolated
software Ethernet peer for the real Linux callbacks; no C80 MCU/DMA/RF model.
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

parser=argparse.ArgumentParser()
parser.add_argument('--mode',choices=['missing-firmware','aon-refusal'],default='missing-firmware')
mode=parser.parse_args().mode
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
    # Complete a fresh empty line after ash's initial TTY setup. Under two
    # concurrent VMs the first prompt previously raced an input flush.
    send('')
    receive_until(prompt)
    command('wait-for-network-service', 'ubus -t 20 wait_for network')
    status = command('MCU-probe-inactive', 'cat /sys/kernel/c80_wifi/status', 'ran=0 finished=0')
    assert 'dma_started=0' in status and 'mcu_released=0' in status
    assert 'cleanup_flags=00000000 owned_bad=0 other_changed=0 rings_bad=00000000' in status
    assert all(x in status for x in ('tx15_before=','rx0_before=','rx1_before=','tx3_before=','patch_bytes=0','command_tx=0/0','fwdl_tx=0/0','main_attempted=0','main_start_attempted=0','main_sync_before=00000000'))
    assert 'download_mode_checked=0 enable_glo=00000000 last_glo=00000000' in status
    assert 'failure_snapshot=0 phase=0 ring=0 slot=0 cpu=00000000 dma=00000000' in status
    assert 'failure_desc=00000000/00000000/00000000/00000000' in status
    assert 'runtime_glo_before=00000000 after=00000000 event_ext=00' in status
    assert 'counter_query_attempted=0 valid=0 category=0 count=0 value=00000000' in status
    assert 'mask_at_ready=00000000 runtime=00000000 cleanup_entry=00000000 first_zero=00000000 after_stop=00000000 before_final=00000000 zero_writes=0' in status
    assert 'attempted=0 armed=0 entries=0 events=0 unexpected=0 faults=00000000 cpu_started=0 cpu_stopped=0' in status
    assert 'irq_mask_before=00000000 enabled=00000000 after=00000000 source_before=00000000 cleared=00000000 seen=00000000 after=00000000 ack_writes=0' in status
    assert 'nvm_source attempted=0 valid=0 linux_errno=0 radio_crc=00000000 raw_crc=00000000 upload_crc=00000000' in status
    assert 'nvm_set attempted=0 valid=0 status=0 get_attempted=0 valid=0 ext=00 source=0 format=0 offset=0 count=0 crc=00000000 equal=0 mismatch=0/0' in status
    assert 'nvm_wait set_limit_ms=60000 get_limit_ms=60000 set_us=0 set_polls=0 get_us=0 get_polls=0 clock_backwards=0' in status
    assert 'mismatch=0/0 padding=0 compared=0' in status
    assert 'devinfo mac_valid=0 complete=0 on_attempted=0 valid=0 status=00000000 ext=00 own=0 count=0' in status
    assert 'devinfo_off attempted=0 valid=0 status=00000000 ext=00 own=0 count=0' in status
    assert 'devinfo_reply on_event=0 dma=0 tail=0 base_read=0 echo=00 off_event=0 dma=0 tail=0 base_read=0 echo=00' in status
    assert 'bss_complete=0 on_attempted=0 valid=0 status=00000000' in status
    assert 'bss_off attempted=0 valid=0 status=00000000' in status
    assert len(status)<4096
    radio = command('radio-probe-inactive','cat /sys/kernel/c80_wifi/radio','complete=0 channel=6 band=0 width_mhz=20')
    assert 'mac_off_final attempted=0 valid=0' in radio and 'RX0_packets=0' in radio
    assert 'rx0_rearm_enabled=1 rearmed=0 publishes=0 cursor=0' in radio
    assert len(radio)<4096
    bcn = command('beacon-probe-inactive','cat /sys/kernel/c80_wifi/beacon','complete=0 SSID=C80-RAM16')
    assert 'target_us=180000000' in bcn and 'TXD_format=3 frame_type=0 subtype=8' in bcn
    assert 'BSS_BASIC_period_TU=0/0 BSS_BASIC_DTIM=0/0' in bcn
    assert 'beacon_off attempted=0 valid=0' in bcn and 'window_started=0' in bcn and len(bcn)<4096
    st = command('beacon-state-inactive','cat /sys/kernel/c80_wifi/state','state=1 snapshots=00')
    assert 'tsf_begin attempted=0 valid=0' in st and 'tsf_end attempted=0 valid=0' in st and 'MMIO_config_writes=0' in st and len(st)<4096
    mgmt = command('management-RX-inactive', 'cat /sys/kernel/c80_wifi/mgmt', 'enabled=1 responses_submitted=0 full_client_stack=0 FCS_verified=0 packet_or_address_saved=0')
    assert 'beacon auth_to_us=0 auth_open_request=0' in mgmt and 'control headers=0' in mgmt and len(mgmt)<4096
    events = command('event-recycle-inactive', 'cat /sys/kernel/c80_wifi/events', 'recycle=1 packets=0 rearmed=0 publishes=0')
    assert 'unmatched=0 short=0 meta_valid=00' in events and 'payload_saved=0' in events and len(events)<4096
    reply = command('auth-reply-inactive','cat /sys/kernel/c80_wifi/reply','enabled=1 maximum_responses=1 captured=0 submitted=0 dma_header_done=0')
    assert 'ring_saved=0 touched=0 programmed=0' in reply and 'air_or_ACK_confirmed=0 full_client_stack=0' in reply and len(reply)<4096
    completion = command('RX1-completion-inactive','cat /sys/kernel/c80_wifi/completion','enabled=1 RX1_types=0/0/0/0/0/0/0/0 non_event=0 unknown=0')
    assert 'TX_free_reports=0 valid=0 bad=0' in completion and 'auth_token_returned=0' in completion and 'pool_release_on_report=0' in completion and len(completion)<4096
    association = command('association-inactive','cat /sys/kernel/c80_wifi/association','enabled=1 maximum_responses=1 captured=0 duplicate=0 late=0')
    assert 'STA_create attempted=0 valid=0' in association and 'STA_delete attempted=0 valid=0' in association and 'submitted=0 DMA_header_done=0 token1_returned=0' in association and 'Linux_netdev=1 DHCP_in_userspace=1 full_wireless_stack=0' in association and len(association)<4096
    data_diag = command('data-echo-inactive','cat /sys/kernel/c80_wifi/data','enabled=0 endpoint=192.168.2.1 client=192.168.2.2 max_ARP=1 max_ICMP=1')
    assert 'ARP captured=0 duplicate=0 bytes=0 submitted=0 header_done=0 token_returned=0' in data_diag and 'ICMP captured=0 duplicate=0 bytes=0 submitted=0 header_done=0 token_returned=0' in data_diag and 'submitted_total=0' in data_diag and 'packet_or_address_logged=0' in data_diag and len(data_diag)<4096
    command('MCU-reject-invalid-input', 'if echo 0 > /sys/kernel/c80_wifi/run; then false; else true; fi')
    command('MCU-invalid-input-keeps-inactive', 'cat /sys/kernel/c80_wifi/status', 'ran=0 finished=0')
    watch = command('watch-inactive','cat /sys/kernel/c80_wifi/watch','watch=1 fault_phase=0')
    assert 'control_target_us=30000000 beacon_target_us=180000000' in watch and 'beacon_max_samples=180001' in watch and 'control started=0 complete=0' in watch and 'beacon started=0 complete=0' in watch and len(watch)<4096
    command('MCU-firmware-present', 'sha256sum /lib/firmware/c80/*', 'ecd3e7f678118016c5ca75aa767629fa98314d4602e40e88b7b9a7b79e75500d')
    if mode=='missing-firmware':
        command('MCU-hide-last-firmware', 'mv /lib/firmware/c80/WIFI_RAM_CODE_7626.bin /tmp/c80-main')
        command('MCU-run-missing-firmware-before-MMIO', 'echo 1 > /sys/kernel/c80_wifi/run')
        expected='ran=1 finished=1 result=-2'
    else:
        command('MCU-run-real-ARM-core-virtual-AON-refusal', 'echo 1 > /sys/kernel/c80_wifi/run')
        expected='ran=1 finished=1 result=2 primary=2'
    status = command('MCU-failure-reports-completion', 'cat /sys/kernel/c80_wifi/status', expected)
    assert 'dma_started=0' in status and 'mcu_released=0' in status and 'pools_retained=0' in status
    assert 'download_mode_checked=0' in status and 'failure_snapshot=0' in status
    assert 'counter_query_attempted=0' in status and 'zero_writes=0' in status
    assert 'fresh_boot_required=1 power_cycle_required=0' in status
    assert 'devinfo mac_valid=0 complete=0 on_attempted=0' in status
    assert 'nvm_source attempted=0 valid=0' in status and 'nvm_set attempted=0' in status
    assert 'attempted=0 armed=0 entries=0 events=0 unexpected=0 faults=00000000 cpu_started=0 cpu_stopped=0' in status
    # AON preconditions follow all six firmware CRCs within stage1;
    # stage2 starts only after those guards pass.
    if mode=='aon-refusal': assert 'phase=1' in status
    radio = command('radio-not-started-after-refusal','cat /sys/kernel/c80_wifi/radio','complete=0 channel=6 band=0 width_mhz=20')
    assert 'mac_on attempted=0 valid=0' in radio and 'listen_started=0' in radio
    assert 'rx0_rearm_enabled=1 rearmed=0 publishes=0' in radio
    st = command('beacon-state-not-started-after-refusal','cat /sys/kernel/c80_wifi/state','state=1 snapshots=00')
    assert 'tsf_begin attempted=0 valid=0' in st and 'tsf_end attempted=0 valid=0' in st
    bcn = command('beacon-not-started-after-refusal','cat /sys/kernel/c80_wifi/beacon','complete=0 SSID=C80-RAM16')
    assert 'BSS_BASIC_period_TU=0/0 BSS_BASIC_DTIM=0/0' in bcn
    assert 'beacon_on attempted=0 valid=0' in bcn and 'window_started=0' in bcn
    watch = command('watch-not-started-after-refusal','cat /sys/kernel/c80_wifi/watch','watch=1 fault_phase=0')
    assert 'control started=0 complete=0' in watch and 'beacon started=0 complete=0' in watch
    if mode=='missing-firmware':
        command('MCU-restore-firmware', 'mv /tmp/c80-main /lib/firmware/c80/WIFI_RAM_CODE_7626.bin')
    mgmt_after = command('management-RX-not-started-after-refusal', 'cat /sys/kernel/c80_wifi/mgmt', 'control headers=0')
    assert mgmt_after[mgmt_after.index('enabled=1'):].split('\nC80_STATUS_')[0] == mgmt[mgmt.index('enabled=1'):].split('\nC80_STATUS_')[0]
    events_after = command('event-recycle-not-started-after-refusal', 'cat /sys/kernel/c80_wifi/events', 'recycle=1 packets=0 rearmed=0 publishes=0')
    assert events_after[events_after.index('recycle=1'):].split('\nC80_STATUS_')[0] == events[events.index('recycle=1'):].split('\nC80_STATUS_')[0]
    reply_after = command('auth-reply-not-started-after-refusal','cat /sys/kernel/c80_wifi/reply','captured=0 submitted=0 dma_header_done=0')
    assert reply_after[reply_after.index('enabled=1'):].split('\nC80_STATUS_')[0] == reply[reply.index('enabled=1'):].split('\nC80_STATUS_')[0]
    completion_after = command('RX1-completion-not-started-after-refusal','cat /sys/kernel/c80_wifi/completion','TX_free_reports=0 valid=0 bad=0')
    assert completion_after[completion_after.index('enabled=1'):].split('\nC80_STATUS_')[0] == completion[completion.index('enabled=1'):].split('\nC80_STATUS_')[0]
    association_after = command('association-not-started-after-refusal','cat /sys/kernel/c80_wifi/association','STA_create attempted=0 valid=0')
    assert association_after[association_after.index('enabled=1'):].split('\nC80_STATUS_')[0] == association[association.index('enabled=1'):].split('\nC80_STATUS_')[0]
    data_after = command('data-echo-not-started-after-refusal','cat /sys/kernel/c80_wifi/data','submitted_total=0')
    assert data_after[data_after.index('enabled=0'):].split('\nC80_STATUS_')[0] == data_diag[data_diag.index('enabled=0'):].split('\nC80_STATUS_')[0]
    command('MCU-once-per-boot', 'if echo 1 > /sys/kernel/c80_wifi/run; then false; else true; fi')
    command('MCU-state-preserved-after-retry', 'cat /sys/kernel/c80_wifi/status', expected)
    command('release' , 'cat /etc/openwrt_release', "DISTRIB_RELEASE='25.12.5'")
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
    iomem = command('iomem-after-relocation', 'cat /proc/iomem', 'Kernel code')
    regions = [(int(a,16), int(b,16), name) for a,b,name in
               re.findall(r'^\s*([0-9a-f]+)-([0-9a-f]+) : (.+)$', iomem, re.M)]
    ram = [r for r in regions if r[2] == 'System RAM']
    code = [r for r in regions if r[2] == 'Kernel code']
    assert ram and all(a >= 0x40200000 and b < 0x42000000 for a,b,_ in ram), ram
    assert code and code[0][0] == 0x40208000, code
    assert b'failed to reserve' not in all_output.lower()
    command('processes', 'ps w', '/sbin/netifd')
    assert b"can't preserve times" not in all_output
    assert b'Kernel panic' not in all_output
    assert b'Out of memory' not in all_output
    if mode=='aon-refusal':
        # Exercise normal BusyBox -> procd -> rc shutdown -> kernel reboot.
        # Synthetic QEMU WDT does not reset; callback must return after its
        # bounded attempts, then QEMU's PSCI handler terminates -no-reboot.
        send('reboot')
        receive_until(b'C80 system reset did not assert; trying other restart handlers',timeout=30)
    else:
        send('poweroff -f')
    process.wait(timeout=10)
    assert process.returncode == 0
    report = {
        'scope': __doc__, 'passed': True, 'physical_ram_bytes': 32 * 1024 * 1024, 'linux_usable_ram_bytes':30 * 1024 * 1024, 'kernel_entry_physical':'0x40208000', 'emi_excluded_from_linux':['0x40000000','0x401fffff'], 'iomem_regions':regions,
        'mem_available_kib_after_services': available,
        'rootfs_cpio_sha256': hashlib.sha256((parent / 'build/usr/initramfs_data.cpio').read_bytes()).hexdigest(),
        'qemu_kernel_sha256': hashlib.sha256((parent / 'build-qemu/arch/arm/boot/zImage').read_bytes()).hexdigest(),
        'commands': results,
        'does_not_emulate_c80_hardware': True, 'normal_reboot_and_C80_callback_before_PSCI_fallback':mode=='aon-refusal', 'MCU_probe_and_sysfs_actual_Linux_driver': True, 'MCU_run_mode':mode,'C80_hardware_accessed':False, 'virtual_MMIO_reads_before_AON_refusal':mode=='aon-refusal', 'MCU_core_real_ARM_CRC_and_DMA_pool_allocation':mode=='aon-refusal',
    }
    from cpio_tools import compare_qemu
    report['identical_hardware_CPIO_entries_except_QEMU_helper'] = compare_qemu((parent/'build/usr/initramfs_data.cpio').read_bytes(),(parent/'build-qemu/usr/initramfs_data.cpio').read_bytes(),(parent/'artifacts/c80-net-selftest').read_bytes())
    report['QEMU_only_software_network_peer_compiled']=True
    report['qemu_CPIO_sha256']=hashlib.sha256((parent/'build-qemu/usr/initramfs_data.cpio').read_bytes()).hexdigest()
    (evidence / f'qemu-{mode}-result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f'OpenWrt QEMU boot with 2MiB EMI excluded passed: {len(results)} command checks, {available} KiB available with 30 MiB Linux RAM inside 32 MiB physical RAM.')
except Exception:
    # Preserve the failure; diagnostics must not turn it into a passing run.
    try:
        send("ps w; ubus list; logread | tail -60")
        diagnostic=receive_until(prompt,timeout=15)
        (evidence / f'qemu-{mode}-failure-diagnostics.txt').write_text(diagnostic)
    except Exception as diagnostic_error:
        (evidence / f'qemu-{mode}-diagnostic-error.txt').write_text(repr(diagnostic_error))
    raise
finally:
    if process.poll() is None:
        process.terminate()
        process.wait(timeout=5)
    rawlog.close()
