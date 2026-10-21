# RAM37: проверка канала1

**Аппаратный результат RAM37:** канал1/2412MHz подтверждён, SSID не найден.
Все четыре raw beacon low16=0, последний снимок через246,90секунды после GTK.
AP была активна246,915секунды, GTK/BMC live,32/32/32команды,0fault; stop
чистый, DMAidle1/MCUstopped1/poolsretained0, клиентов/EAPOL/data нет.
Смена канала не восстановила видимость. Следующий опыт — [RAM38 с полным
профилем BMC](../openwrt-ram38-bmc-profile/); физическая причина ещё неизвестна.

Снимки161340086/161350049/161360018/408260096us, guard0; интервал после GTK
246900078us. MCU команды32/32/32,9reuses,0fault;63/63totalTX,15817RX.
result/primary/cleanup/critical0, scheduler restored; MemAvailable8184KiB.
Это полный отчёт владельца без новых подключений; сырой лог не публикуется.
Ноль raw MIB не доказывает конкретную причину отсутствия RF.

Программные проверки при выпуске:

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

QEMU synthetic key backend не эмулирует физические MCU/CCMP/DMA/RF. WPA2-клиент
на физической RAM37 не проверен, поскольку SSID не появился.
Все beacon/key snapshots RAM36 сохранены; MIB может очищаться при capture.
Один клиент,CCK/20MHz/MTU1400,без live channel switch/AP restart в одной загрузке.
Архив и source snapshot неизменяемы; аппаратный результат описан выше.
