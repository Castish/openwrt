#!/usr/bin/env python3
"""Tie final RAM8 files to completed checks; write metadata and instructions."""
from pathlib import Path
import hashlib,json,zlib
r=Path(__file__).resolve().parent;e=r/'evidence'
assert not (r/'c80-openwrt-ram8-irq.zip').exists()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
log=(r/'verification-core.log').read_text()
assert 'PASS:106 actual-core scenarios + 18 IRQ gate cases' in log
assert len([x for x in log.splitlines() if x.startswith('PASS ')])==124
for name,count in [('stock-download-traces',23),('stock-main-traces',27),('stock-dma-mode-traces',15),('stock-query-traces',8),('stock-irq-traces',13)]:
 assert json.loads((e/(name+'.json')).read_text())['cases_passed']==count
wrapper=json.loads((e/'irq-wrapper-result.json').read_text())
assert wrapper['passed'] and wrapper['cases_passed']==12
text=(r/'c80_mcu_transport.c').read_text()
callbacks=text[text.index('static irqreturn_t c80_mcu_irq'):text.index('static ssize_t status_show')]
assert wrapper['actual_callback_source_sha256']==hashlib.sha256(callbacks.encode()).hexdigest()
assert len(json.loads((e/'rootfs-elf-closure.json').read_text()))==57
assert len(json.loads((r/'FIRMWARE-SOURCES.json').read_text())['files'])==6
qemu={}
for mode in ('missing-firmware','aon-refusal'):
 q=json.loads((e/f'qemu-{mode}-result.json').read_text());assert q['passed']
 assert sha(r/'build/usr/initramfs_data.cpio')==q['rootfs_cpio_sha256']
 assert sha(r/'build-qemu/arch/arm/boot/zImage')==q['qemu_kernel_sha256']
 qemu[mode]=len(q['commands'])
 if mode=='aon-refusal':assert q['normal_reboot_and_C80_callback_before_PSCI_fallback']
assert 'All twenty files match' in (r/'artifacts/patch-verification.txt').read_text()
assert json.loads((e/'ram7-change-scope.json').read_text())['passed']
restart=json.loads((e/'restart-result.json').read_text());assert restart['passed'] and restart['cases_passed']==8
assert restart['Linux_vmlinux_sha256']==sha(r/'build/vmlinux')
d=json.loads((e/'decompressor-result.json').read_text())
assert d['passed'] and len(d['checks'])==6 and d['zimage_sha256']==sha(r/'c80-openwrt-ram8-irq-zImage')
h=json.loads((e/'handoff-verification.json').read_text())
assert len(h['cases'])==5 and all(x['status']=='pass' for x in h['cases'])
assert h['payload_sha256']==sha(r/'c80-openwrt-ram8-handoff.bin')
records=[]
for address,name in [(0x41000000,'c80-openwrt-ram8-irq-zImage'),(0x40f00000,'c80-openwrt-ram8-irq.dtb'),(0x40e00000,'c80-openwrt-ram8-handoff.bin')]:
 data=(r/name).read_bytes()
 records.append({'file':name,'address':hex(address),'bytes':len(data),'crc32':f'{zlib.crc32(data):08x}','sha256':sha(r/name)})
assert (r/'c80-openwrt-ram8-irq-zImage').read_bytes()==(r/'build/arch/arm/boot/zImage').read_bytes()
assert (r/'c80-openwrt-ram8-irq.dtb').read_bytes()==(r/'build/arch/arm/boot/dts/mediatek/mt7626-archer-c80-v1-ram.dtb').read_bytes()
assert (r/'c80-openwrt-ram8-handoff.bin').read_bytes()==(r.parent/'openwrt-ram7-query/c80-openwrt-ram7-handoff.bin').read_bytes()
assert (r/'c80-script-runner.bin').stat().st_size==4732
lines=[x for x in (r/'c80-start.txt').read_text().splitlines() if not x.startswith('#')]
assert len(lines)==6 and lines[0]=='C80SCRIPT1' and lines[-2]=='go 40e00000'
for row in records:
 assert f"load {int(row['address'],16):08x} {row['file']} {row['bytes']:08x} {row['crc32']}" in lines
p=json.loads((r.parent/'openwrt-ram7-query/PROVENANCE.json').read_text())
p.update(kernel='6.12.113-c80-openwrt-ram8-irq',load_files=records,script_bytes=(r/'c80-start.txt').stat().st_size,
 hardware_tested=False,physical_runtime_query_tested=False,physical_RX1_CPU_IRQ_tested=False,
 parent_RAM7_main_runtime_GET_and_cleanup_hardware_passed=True,
 source_scope='evidence/ram7-change-scope.json',
 scope='One-shot RX1 IRQ route test during the exact hardware-proven runtime GET; GIC243/SPI211 active-low through MT_SYSIRQ. No AP/RF/NOR commands.',
 not_proven=['physical RX1 CPU interrupt on candidate route','RF/calibration/AP/association','cold power rail-cut equivalence','flash installation'])
p.pop('parent_RAM6_main_result',None)
p['parent_RAM7_result']={'result':0,'primary':0,'cleanup':0,'critical':0,'TX':41,'RX':10,'runtime_GET_valid':1,'IRQ_mask_after':'00000000'}
p['download_mode']['runtime_mode_off_hardware_unproven']=False
p['checks'].update(actual_OEM_ARM_IRQ_contract=13,actual_C_core_ASan_UBSan=106,
 shared_IRQ_gate_ASan_UBSan=18,actual_Linux_IRQ_callbacks_with_synthetic_services=12,QEMU_command_checks=qemu)
p['IRQ_mask_cleanup']={'runtime_enable_mask':'00000002','W1C_only_RX1_bit1':True,
 'CPU_and_peripheral_one_shot':True,'CPU_disable_and_synchronize_before_pool_free':True,
 'strict_zero_readback_after_stop_and_controls_restore':True,
 'main_and_runtime_stage_snapshots':True}
p['IRQ_test']={'raw_GIC_ID':243,'SPI':211,'controller':'MT_SYSIRQ active-low','source_mask':'00000002',
 'initial_CPU_IRQ':'IRQF_NO_AUTOEN','enable_only_after_main_ready':True,
 'CPU_IRQ_required_despite_valid_DMA_response':True,'missing_IRQ_result':25,'invalid_IRQ_result':26,
 'IRQ_handler_waits_allocations_or_descriptor_access':False,
 'physical_route_proven':False}
(r/'PROVENANCE.json').write_text(json.dumps(p,indent=2)+'\n')
(e/'script-result.json').write_text(json.dumps({'passed':True,'records':records,'script_bytes':p['script_bytes'],'unchanged_hardware_confirmed_runner':True},indent=2)+'\n')
readme='''# OpenWrt RAM8: прерывание при ответе Wi-Fi MCU

RAM7 аппаратно прошла: основной микрокод запущен, штатный GET получил ответ,
TX41/RX10, IRQ-маска восстановлена в ноль, result/cleanup/critical=0.
RAM8 проверяет доставку RX1-прерывания до CPU на маршруте из OEM-кода:
GIC ID243 / SPI211, active-low через MT_SYSIRQ. Физический маршрут ещё
не подтверждён. Точка доступа и радиопередача в этот тест не входят.

## Пять файлов в TFTP

В корень TFTP скопируйте c80-script-runner.bin, новый c80-start.txt
(замените прежний) и три файла из таблицы. ПК оставьте в LAN1,
192.168.0.3/24.

| Файл | Байт | CRC32 |
|---|---:|---|
'''+''.join(f"| {x['file']} | {x['bytes']} | {x['crc32']} |\n" for x in records)+'''
## Загрузка и тест

В текущем OpenWrt выполните `reboot`, остановите autoboot до `MT7626>`.
Дополнительно отключать питание сейчас не требуется. Команды U-Boot
вводите по одной:

```text
setenv autostart no
tftpboot 40280000 c80-script-runner.bin
```

Только после успешной передачи 4732 байт:

```text
go 40280000
```

В новом OpenWrt вводите короткие команды по одной, с ожиданием приглашения.
Не вставляйте сразу весь блок: polling UART ранее терял окончания строк.

```sh
uname -r
cd /sys/kernel
cd c80_wifi
cat status
```

Проверьте версию `6.12.113-c80-openwrt-ram8-irq` и `ran=0 finished=0`.
Только при их совпадении выполните отдельно:

```sh
echo 1 > run
```

Дождитесь приглашения и выполните по одной:

```sh
cat status
cat /proc/interrupts
free
```

Пришлите весь вывод от uname до free, включая стадии ядра. Оставайтесь
в OpenWrt после теста. Повторять run в этой загрузке не нужно.

## Что требуется для успеха

result/primary/cleanup/critical=0; прежний main3/3/startACK0/ready1,
counter_query_valid1/category5/count1. Счётчик может быть нулевым.
Ожидаются TX41/41 (command10/10 + FWDL31/31), RX10; при уже готовом patch
возможны TX35/RX6. Команда MCU осталась побайтно прежней.

Новые строки должны показать attempted1/armed0/entries1/events1,
unexpected0/faults0, cpu_started1/cpu_stopped1. В /proc/interrupts
ожидается строка c80-mcu-rx1 / MT_SYSIRQ211 с одним входом. Linux-номер
IRQ выделяется динамически: не подменяйте его числом из старого лога.

irq_mask_before обычно20000000, enabled00000002, after00000000.
source_before/cleared/seen/after и ack_writes сохраняются полностью;
другие source-биты не очищаются. Старый RX1 pending должен очиститься
до включения IRQ, затем нужен новый вход в обработчик с RX1 bit1.
Если после W1C приходит новый пакет при уже нулевой маске, новый pending
допустим и остаётся видимым в отчёте.

Вход в обработчик немедленно отключает CPU IRQ и peripheral mask.
Он не ждёт, не выделяет память и не обращается к DMA-дескрипторам.
Перед освобождением pool выполняется synchronize_irq. DMA/MCU затем
останавливаются как в RAM7: idle1/stopped1/retained0, writable ring-поля,
owned controls, GLO10001870 и финальная нулевая маска проверяются строго.

Новый result25 означает: ответ в DMA получен, но нужное прерывание не
наблюдалось. result26 — отказ clear/mask/readback либо неверный IRQ source.
Даже корректный ответ не превращает эти отказы в pass. Прежние ошибки
транспорта сохраняются; critical80/81 закрепляют pool до нового boot.

## Локальная проверка и границы

Проверены 106 сценариев настоящего C-core, 18 сценариев общего IRQ-кода
и 12 сценариев настоящих Linux callbacks с синтетическими IRQ/locks/MMIO,
ASan/UBSan. Последние проверяют баланс IRQF_NO_AUTOEN, запоздавший IRQ,
неверный маршрут и событие, возникшее во время остановки.
13 сценариев исполнили OEM ARM ISR/mask helper/route setup. Службы TPOS,
W1C/MMIO и аппаратура в этих моделях синтетические; MCU не эмулируется.
Старые 23 patch / 27 main / 15 mode / 8 runtime ARM evidence сохранены.

Новая сборка прошла QEMU userspace/refusal/reboot, actual ARM decompressor6,
handoff5/restart8, 57 ELF ABI/closure, полный CPIO/compiled DTB/RAM bounds
и точное применение 20-file Linux patch. QEMU использует виртуальный GIC
с high-level IRQ, без MT_SYSIRQ и Wi-Fi MCU, поэтому не проверяет C80 route.

От RAM7 изменены только два MCU-файла Linux и IRQ-свойства Wi-Fi в DTS.
Rootfs, Ethernet/DSA/restart/handoff и шесть общих OEM blobs прежние.
Нижние 2МиБ EMI остаются no-map; NOR read-only, flash_writes=0. MCU
намеренно останавливается после опыта. RF/AP/ассоциация/калибровки пока
не проверены; внутреннее состояние MCU требует нового boot перед опытом.

Выданные RAM7/старые архивы не изменены. Индивидуальные калибровки,
MAC/пароли, полный TPOS/U-Boot/NOR сюда не включены. OEM-лицензии сохранены.
'''
(r/'README.md').write_text(readme)
print(json.dumps({'load_files':records,'checks':p['checks'],'script_bytes':p['script_bytes']},indent=2))
