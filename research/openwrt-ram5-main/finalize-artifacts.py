#!/usr/bin/env python3
"""Verify final RAM5 image/check ties and write reviewable bundle metadata."""
from pathlib import Path
import hashlib,json,zlib
r=Path(__file__).resolve().parent;e=r/'evidence';assert not (r/'c80-openwrt-ram5-main.zip').exists()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
log=(r/'verification-core.log').read_text();assert 'PASS:71' in log
assert len([x for x in log.splitlines() if x.startswith('PASS ')])==71
assert json.loads((e/'stock-download-traces.json').read_text())['cases_passed']==23
assert json.loads((e/'stock-main-traces.json').read_text())['cases_passed']==27
assert len(json.loads((e/'rootfs-elf-closure.json').read_text()))==57
fw=json.loads((r/'FIRMWARE-SOURCES.json').read_text());assert len(fw['files'])==6
qemu={}
for mode in ('missing-firmware','aon-refusal'):
 q=json.loads((e/f'qemu-{mode}-result.json').read_text());assert q['passed']
 assert sha(r/'build/usr/initramfs_data.cpio')==q['rootfs_cpio_sha256']
 assert sha(r/'build-qemu/arch/arm/boot/zImage')==q['qemu_kernel_sha256']
 qemu[mode]=len(q['commands'])
 if mode=='aon-refusal':assert q['normal_reboot_and_C80_callback_before_PSCI_fallback']
assert 'All twenty files match' in (r/'artifacts/patch-verification.txt').read_text()
assert json.loads((e/'ram4-change-scope.json').read_text())['passed']
restart=json.loads((e/'restart-result.json').read_text());assert restart['passed'] and restart['cases_passed']==8
assert restart['Linux_vmlinux_sha256']==sha(r/'build/vmlinux')
decompressor=json.loads((e/'decompressor-result.json').read_text());assert decompressor['passed']
assert decompressor['zimage_sha256']==sha(r/'c80-openwrt-ram5-main-zImage') and len(decompressor['checks'])==6
handoff=json.loads((e/'handoff-verification.json').read_text());assert len(handoff['cases'])==5 and all(x['status']=='pass' for x in handoff['cases'])
assert handoff['payload_sha256']==sha(r/'c80-openwrt-ram5-handoff.bin')
records=[]
for address,name in ((0x41000000,'c80-openwrt-ram5-main-zImage'),(0x40f00000,'c80-openwrt-ram5-main.dtb'),(0x40e00000,'c80-openwrt-ram5-handoff.bin')):
 data=(r/name).read_bytes();records.append({'file':name,'address':hex(address),'bytes':len(data),'crc32':f'{zlib.crc32(data):08x}','sha256':sha(r/name)})
assert (r/'c80-openwrt-ram5-main-zImage').read_bytes()==(r/'build/arch/arm/boot/zImage').read_bytes()
assert (r/'c80-openwrt-ram5-main.dtb').read_bytes()==(r.parent/'openwrt-ram4-patch/c80-openwrt-ram4-patch.dtb').read_bytes()
assert (r/'c80-openwrt-ram5-handoff.bin').read_bytes()==(r.parent/'openwrt-ram4-patch/c80-openwrt-ram4-handoff.bin').read_bytes()
assert (r/'c80-script-runner.bin').stat().st_size==4732
lines=[x for x in (r/'c80-start.txt').read_text().splitlines() if not x.startswith('#')];assert len(lines)==6 and lines[0]=='C80SCRIPT1' and lines[-2]=='go 40e00000'
for row in records:assert f"load {int(row['address'],16):08x} {row['file']} {row['bytes']:08x} {row['crc32']}" in lines
p={'kernel':'6.12.113-c80-openwrt-ram5-main','userspace':'OpenWrt25.12.5 r33051-f5dae5ece4; unchanged35packages/57ELF','load_files':records,'script_bytes':(r/'c80-start.txt').stat().st_size,'hardware_tested':False,'physical_main_download_start_state3_tested':False,'parent_RAM4_patch_download_readiness_and_cleanup_passed':True,'parent_software_reboot_after_MCU_confirmed':True,'scope':'Exact supplied WIFI_RAM_CODE_7626.bin after patch, 3 regions/25616 payload bytes/29fragments, start flags0/address0 then sync state3; no AP/RF/IRQ-enable/NOR commands','main_firmware':{'file':'WIFI_RAM_CODE_7626.bin','bytes':25808,'CRC32':'92c09901','SHA256':'76a9a4fb62be68725fba016d0814911255cf62b819d41760198dc7e3911322b5','regions':[{'MCU_address':'0x20400','bytes':2896,'chunks':4},{'MCU_address':'0x2010000','bytes':1584,'chunks':2},{'MCU_address':'0x40100000','bytes':21136,'chunks':23}],'initial_sync_state':1,'post_start_sync_state':3,'sync_CPU_address':'0x180c1140','sync_mask':'0xe'},'checks':{'actual_OEM_ARM_patch_contract':23,'actual_OEM_ARM_main_contract':27,'actual_C_core_ASan_UBSan':71,'QEMU_command_checks':qemu,'actual_ARM_decompressor':6,'actual_ARM_handoff':5,'actual_ARM_restart':8,'ELF_ABI_closure':57,'Linux_patch_files_apply_exact':20,'new_build_compiled_and_verified':True},'source_scope':'evidence/ram4-change-scope.json','rootfs_firmware_scope':'Six exact generic user-supplied OEM blobs; FIRMWARE-SOURCES.json; no individual calibration','not_proven':['physical main transfer/start/generic ACK/state3','Wi-Fi IRQ','RF/calibration/AP/association','cold power equivalence','flash installation'],'cleanup':'Same owned controls, GLO, mask and writable4rings; pin coherent pool if MCU/DMA stop fails','fresh_boot_required_after_attempt':True,'new_power_off_requested_for_next_test':False,'issued_parent_artifacts_immutable':True}
(r/'PROVENANCE.json').write_text(json.dumps(p,indent=2)+'\n')
(e/'script-result.json').write_text(json.dumps({'passed':True,'records':records,'script_bytes':p['script_bytes'],'unchanged_hardware_confirmed_runner':True},indent=2)+'\n')
readme='''# OpenWrt RAM5: загрузка и запуск основного Wi-Fi-кода

RAM4 аппаратно загрузила patch и подтвердила ready1 без ошибок. RAM5
загружает точный WIFI_RAM_CODE_7626.bin:3области/25616payload байт,
отправляет start и ждёт рабочее состояние MCU3. Это новая аппаратная
проверка, ещё не выполненная. Настройка точки доступа и RF-команды пока
не добавлены. NOR read-only, образ работает только в RAM.

## Пять файлов в TFTP

Скопируйте в корень TFTP c80-script-runner.bin, новый c80-start.txt
(заменить прежний) и три файла из таблицы. Компьютер остаётсяLAN1,
192.168.0.3/24.

|Файл|Байт|CRC32|
|---|---:|---|
'''+''.join(f"|{x['file']}|{x['bytes']}|{x['crc32']}|\n" for x in records)+'''
## Загрузка из текущего OpenWrt

В текущей оболочке выполните `reboot`, затем остановите Autoboot до
`MT7626>`. Дополнительное отключение питания сейчас не требуется.
В U-Boot по одной:

```text
setenv autostart no
tftpboot 40280000 c80-script-runner.bin
```

Только после успешной передачи4732байт:

```text
go 40280000
```

Помощник проверит файлы по размерам/CRC и выполнит весь сценарий.
Новое ядро:6.12.113-c80-openwrt-ram5-main. После Enter/root shell короткие
команды по одной, с ожиданием prompt; лучше вручную, без вставки всего блока:

```sh
uname -r
cd /sys/kernel
cd c80_wifi
cat status
```

Если ran=0/finished=0, отдельно:

```sh
echo 1 > run
```

Дождитесь prompt, затем отдельно:

```sh
cat status
free
```

Пришлите весь вывод от uname до free со стадиями ядра. После опыта
оставайтесь в OpenWrt. Повторный run в этой загрузке не нужен; guards
не обходить. Короткие команды сохраняют символы на polling UART.

## Успешный результат

Ожидаются result/primary/cleanup/critical0. Patch по-прежнему1808B/2chunks,
address/finish0, сем2/release3/ready1/sem_held0. Затем main_attempted1,
regions3/3, bytes25616/chunks29, main_address_valid7/status0/0/0,
main_region_bytes2896/1584/21136, chunks4/2/23. main_start_attempted1,
valid1/status0 и **ready1**, main_sync_after с bits3:1=3 (masked raw6).
Это отдельная проверка рабочего состояния после ACK, не только передачи.

При свежем patch ожидаются TX40/40:command9/9+FWDL31/31, RX9, последняя
wire sequence10. Если первый семафор ужеready1, patch пропускается:
main всё равно загружается; тогда TX34/RX5, command5/FWDL29. Ни один
активный packet buffer не используется повторно; sequence повторяется1..15.

Очистка: DMAidle1/MCUstopped1/pools_retained0, GLO/mask восстановлены,
cleanup_flags/owned_bad/rings_bad0, writable поля всех4колец возвращены.
Read-only DMA indices и чужие control changes видны отдельно. Controlb0e20
вне owned208001 может остаться сохранённым, как в RAM3/RAM4. Pending IRQ
source остаётся masked. При critical-stop отказе pool закреплён.

Новые коды:21 — не подтверждён исходный sync state1 (raw показан),
22 — start ACK получен, но рабочее состояние3 не подтверждено.18 — MCU
вернул ошибку address/start;19 — FWDL timeout. В статусе остаются номер
области, байты/блоки, ACK и sync. После ошибки start не отправляется дальше.

## Проверки и границы

27 сценариев настоящего OEM ARM parser/selector/loader/state/sequence,
23 прежних patch-сценария,71 actual-C ASan/UBSan сценарий с39 точными
пакетами OEM.33+31 QEMU проверки userspace/sysfs/firmware refusal/reboot,
6 ARM decompressor/5handoff/8restart,57ELF и20-fileLinuxpatch прошли.
MMIO, DMA и ответы MCU в моделях синтетические; аппаратура C80 проверяется
этим запуском. Контракт — evidence/main-contract.md и stock-main-traces.json.

Все шесть OEM файлов точные, длины/CRC проверяются до MMIO. Сохраняется
2MiB no-map EMI. main addresses — адреса MCU в пакетах, не CPU MMIO.
Ethernet/DSA, системный restart, DTB, handoff и runner исходники прежние.
root/settings вRAM, после reboot загрузить образ заново. Cold init всей
платы, AP/ассоциация/калибровки/RF и Wi-Fi IRQ ещё не подтверждены.
Образ не предназначен для flash installation; индивидуальные radio/MAC/
пароли, полный TPOS, U-Boot и NOR backup не включены. Лицензии OEM сохранены.
'''
(r/'README.md').write_text(readme)
print(json.dumps({'load_files':records,'checks':p['checks'],'script_bytes':p['script_bytes']},indent=2))
