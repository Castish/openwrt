#!/usr/bin/env python3
"""Tie final RAM4 binaries to source, packet oracles, native and ARM checks."""
from pathlib import Path
import hashlib,json,subprocess,zlib
r=Path(__file__).resolve().parent;e=r/'evidence';assert not (r/'c80-openwrt-ram4-patch.zip').exists()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert 'PASS:53' in (r/'verification-core.log').read_text()
assert len([x for x in (r/'verification-core.log').read_text().splitlines() if x.startswith('PASS ')])==53
assert json.loads((e/'stock-download-traces.json').read_text())['cases_passed']==23
assert len(json.loads((e/'rootfs-elf-closure.json').read_text()))==57
qemu={}
for mode in ('missing-firmware','aon-refusal'):
 q=json.loads((e/f'qemu-{mode}-result.json').read_text());assert q['passed']
 assert sha(r/'build/usr/initramfs_data.cpio')==q['rootfs_cpio_sha256']
 assert sha(r/'build-qemu/arch/arm/boot/zImage')==q['qemu_kernel_sha256']
 qemu[mode]=len(q['commands'])
 if mode=='aon-refusal':assert q['normal_reboot_and_C80_callback_before_PSCI_fallback']
assert 'All twenty files match' in (r/'artifacts/patch-verification.txt').read_text()
assert json.loads((e/'ram3-change-scope.json').read_text())['passed']
restart=json.loads((e/'restart-result.json').read_text());assert restart['passed'] and restart['cases_passed']==8
assert restart['Linux_vmlinux_sha256']==sha(r/'build/vmlinux')
decompressor=json.loads((e/'decompressor-result.json').read_text());assert decompressor['passed']
assert decompressor['zimage_sha256']==sha(r/'c80-openwrt-ram4-patch-zImage') and len(decompressor['checks'])==6
handoff=json.loads((e/'handoff-verification.json').read_text());assert len(handoff['cases'])==5
assert all(x['status']=='pass' for x in handoff['cases'])
assert handoff['payload_sha256']==sha(r/'c80-openwrt-ram4-handoff.bin')
records=[]
for address,name in ((0x41000000,'c80-openwrt-ram4-patch-zImage'),(0x40f00000,'c80-openwrt-ram4-patch.dtb'),(0x40e00000,'c80-openwrt-ram4-handoff.bin')):
 data=(r/name).read_bytes();records.append({'file':name,'address':hex(address),'bytes':len(data),'crc32':f'{zlib.crc32(data):08x}','sha256':sha(r/name)})
assert (r/'c80-openwrt-ram4-patch-zImage').read_bytes()==(r/'build/arch/arm/boot/zImage').read_bytes()
assert (r/'c80-openwrt-ram4-patch.dtb').read_bytes()==(r.parent/'openwrt-ram3-mcu/c80-openwrt-ram3-mcu.dtb').read_bytes()
assert (r/'c80-openwrt-ram4-handoff.bin').read_bytes()==(r.parent/'openwrt-ram3-mcu/c80-openwrt-ram3-handoff.bin').read_bytes()
assert (r/'c80-script-runner.bin').stat().st_size==4732
lines=[x for x in (r/'c80-start.txt').read_text().splitlines() if not x.startswith('#')];assert len(lines)==6 and lines[0]=='C80SCRIPT1' and lines[-2]=='go 40e00000'
for row in records:assert f"load {int(row['address'],16):08x} {row['file']} {row['bytes']:08x} {row['crc32']}" in lines
p={'kernel':'6.12.113-c80-openwrt-ram4-patch','userspace':'OpenWrt25.12.5 r33051-f5dae5ece4; unchanged 35 packages/57 ELF','load_files':records,'script_bytes':(r/'c80-start.txt').stat().st_size,'hardware_tested':False,'physical_patch_download_tested':False,'parent_RAM3_MCU_DMA_and_cleanup_hardware_passed':True,'parent_software_only_reboot_after_MCU_confirmed':True,'scope':'Patch-only, 1808-byte payload through FWDL3 in 960+848 fragments; query ready after release; no main-start/RF/AP/IRQ-enable/NOR commands','checks':{'actual_OEM_ARM_parser_loader_headers_kicks_generic_status':23,'actual_C_core_ASan_UBSan':53,'QEMU_command_checks':qemu,'actual_ARM_decompressor':6,'actual_ARM_handoff':5,'actual_ARM_restart':8,'ELF_ABI_closure':57,'Linux_patch_files_apply_exact':20,'new_build_compiled_and_verified':True},'source_scope':'evidence/ram3-change-scope.json','rootfs_firmware_scope':'Five exact generic user-supplied OEM blobs in FIRMWARE-SOURCES.json; no WIFI_RAM_CODE_7626 main image','not_proven':['physical patch/generic-response/readiness handshake','Wi-Fi IRQ','full main firmware boot','RF/calibration/AP/association','cold power equivalence','flash installation'],'cleanup':'Restore only owned controls, GLO and all writable TX15/RX0/RX1/TX3 ring fields; pin all coherent memory if MCU/DMA stop fails','fresh_boot_label':'Fresh boot after each attempt; power_cycle_required only for critical stop failure. Normal reboot hardware confirmed on parent; electrical cold-power equivalence not claimed.','issued_parent_artifacts_immutable':True}
(r/'PROVENANCE.json').write_text(json.dumps(p,indent=2)+'\n')
(e/'script-result.json').write_text(json.dumps({'passed':True,'records':records,'script_bytes':p['script_bytes'],'unchanged_hardware_confirmed_runner':True},indent=2)+'\n')
readme=f'''# OpenWrt RAM4: загрузка штатного Wi-Fi patch

RAM3 аппаратно прошла весь MCU/DMA-тест и восстановление полей. RAM4
добавляет следующий этап: patch1808B через FWDL3, finish/release и повторный
get семафора со статусом1. Это новая аппаратная проверка, ещё не выполненная.
Основной Wi-Fi-код, AP и RF-команды пока не запускаются. NOR остаётся read-only.

## Файлы TFTP

В корень TFTP скопируйте пять файлов из этого архива: c80-start.txt
(заменить прежний), c80-script-runner.bin и три файла из таблицы.
Компьютер остаётсяLAN1,192.168.0.3/24.

|Файл|Байт|CRC32|
|---|---:|---|
'''+''.join(f"|{x['file']}|{x['bytes']}|{x['crc32']}|\n" for x in records)+f'''
## Перезапуск из текущего OpenWrt

В текущей оболочке выполните `reboot`, дождитесь U-Boot и остановите
Autoboot до `MT7626>`. Затем по одной:

```text
setenv autostart no
tftpboot 40280000 c80-script-runner.bin
```

Только после успешной передачи4732байт:

```text
go 40280000
```

Помощник сам выполнит четыре шага из c80-start.txt и проверит размеры/CRC.
Новое ядро должно сообщить `6.12.113-c80-openwrt-ram4-patch`.
После Enter/root shell вводите короткие строки по одной, лучше вручную:

```sh
uname -r
cd /sys/kernel
cd c80_wifi
cat status
```

Если `ran=0 finished=0`, отдельно:

```sh
echo 1 > run
```

Дождитесь prompt, затем отдельно:

```sh
cat status
free
```

Пришлите вывод от версии до free вместе со стадиями ядра. После опыта
оставайтесь в OpenWrt; повторный run в этой загрузке не требуется.
При отказе guards его не обходить. Длинные вставки UART теряли символы,
поэтому не вставляйте весь блок сразу. Дополнительный физический power-off
сейчас не требуется: normal reboot уже аппаратно проверен после MCU.

## Что проверяем

При новой загрузке patch ожидаются result/primary/cleanup/critical0,
get/status2, patch_address_valid1/status0, finish_valid1/status0,
patch_bytes1808/chunks2/uploaded1, release/status3, ready_valid1/ready_status1,
sem_held0. Суммарно TX7, command_tx5/5, fwdl_tx2/2, RX5 с правильными
sequence/EID; все writable TX15/RX0/RX1/TX3 поля восстановлены,
cleanup_flags/owned_bad/rings_bad0, DMAidle1/MCUstopped1/pools_retained0.
Если первый get уже вернёт1, загрузка patch пропускается и это видно по
uploaded0/bytes0; такой результат не доказывает передачу через FWDL.

Статусы address/finish приходят generic EID1/event+8; семафор — EID4.
Пакеты и порядок восстановлены из настоящего OEM ARM-кода. 23 ARM-сценария
и53 native ASan/UBSan сценария прошли с синтетическими MCU/DMA/MMIO ответами.
Совпадение с реальным MCU проверяется этим запуском, а не подменяется моделью.
При явном отказе MCU пробуется release; после transport timeout идёт stop.
Если повторный get возвращает2, новый семафор освобождается, result20
сообщает, что patch readiness не подтверждена. Подробнее — evidence/download-contract.md.

Control18002150 может снова изменить биты вне маски208001: они сохраняются
и печатаются как other_changed/control_diff. Read-only DMA indices не
возвращаются обычной записью; показаны отдельно. IRQmask остаётся0,
pending source не очищается. При critical-stop отказе pool закреплён.
Теперь статус требует fresh_boot после попытки; power_cycle_required
выставляется только при critical. Электрическая эквивалентность reboot
отключению всех питающих шин не заявляется.

Ethernet, DSA, DTB/handoff/runner и системный restart исходники неизменны
относительно RAM3. Корень/настройки в RAM; после reboot образ загружается
заново. Пять OEM blobs точные, лицензии сохранены; нет индивидуальных
калибровок, MAC/паролей, полного TPOS, U-Boot или NOR backup.

Исходники/конфигурация/полный20-файловый Linux patch, diffRAM3→RAM4,
проверки и manifest включены. Пакет предназначен для загрузки в RAM через
TFTP и не является образом установки во flash.
'''
(r/'README.md').write_text(readme)
print(json.dumps({'load_files':records,'checks':p['checks'],'script_bytes':p['script_bytes']},indent=2))
