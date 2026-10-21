# RAM37: проверка канала1

На физическом роутере RAM37 ещё не проверена. Владелец запросил смену канала
после двух запусков RAM36: SSID виден/357маяков, затем не виден/0маяков.
Причина непостоянной передачи не установлена; помехи канала6 не доказаны.

- 3700 свежих native ASan/UBSan cases:3624 базовых и76 selected-channel.
  Настоящий полный core проверен с независимыми OEM пакетами для1/6,
  с success/reject/timeout и отказом неверного канала до MMIO.
- 19 свежих OEM ARM cases, включая6 CHANNEL/PATH/wrapper для1/6.
  В соответствующих140-byte пакетах отличаются только offsets64/65.
  Калибровка и поля мощности не менялись; RF helpers синтетические.
- 40 настоящих hostapd/cfg80211/OpenWrt QEMU checks: канал1/2412MHz,
  отказ канала6 до AP request, WPA2 с независимыми PMK/PTK/MIC/AES unwrap,
  неправильный MIC, два подключения,13 Linux DHCP/IP/TCP cases и pinned SSH.
  Сохранены32 actual ARM report callback cases,13 startup-removal checks.
- 86729 source entries/32-файловый patch восстановлены без fuzz/offsets,
  601 host rootfs entries/607CPIO,3 recovery cases,45 прежних signed packages,
  66ELF, decompressor6/handoff5/restart8 и размещение ядра сверены.

QEMU synthetic key backend не эмулирует физические MCU/CCMP/DMA/RF. Нужны
поиск C80-RAM37 и подключение одного WPA2/DHCP клиента на устройстве.
Все beacon/key snapshots RAM36 сохранены; MIB может очищаться при capture.
Один клиент,CCK/20MHz/MTU1400,без live channel switch/AP restart в одной загрузке.
Архив и source snapshot неизменяемы; аппаратный результат будет отдельным.
