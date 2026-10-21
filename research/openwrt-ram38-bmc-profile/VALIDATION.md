# RAM38: профиль BMC обычного AP

Аппаратный тест RAM38 ожидается. В RAM37 подтверждены канал1/2412MHz и
отсутствие SSID; четыре raw beacon low16 равны0, stop чистый, клиентов нет.

Выполнен настоящий OEM ARM конструктор обычного AP request40361efc для
open/CCMP: BMC feature mask0x2101. Настоящий STA builder402ede60 для0x2001
и0x2101 формирует244 и252байта соответственно; разница — tag8/len8/flags1
между BASIC и WTBL. Некоторые OS/BSS helpers синтетические. RAM38 повторяет
252-байтовый профиль. Порядок BMC/GTK и канал1 сохранены. Причинная связь
с видимостью SSID ещё не проверена; RF-исправление не заявляется.

- 3712 свежих native ASan/UBSan cases, включая12 новых BMC exact-oracle,
  guard-page252/28 и отказов установки GTK при9ошибках BMC create.
  Все прежние security/channel/beacon_diag suites выполнены.
- 23 свежих OEM ARM cases:13 security,6channel,2normal-request,2BMC-profile.
- 40 настоящих hostapd/cfg80211/OpenWrt QEMU checks, включая независимые
  PMK/PTK/MIC/AES unwrap, неверный MIC, два подключения,13 Linux DHCP/IP/TCP,
  pinned SSH login и32 actual ARM report callback cases. Дополнительно13
  startup-removal checks. MemAvailable6496KiB при32MiB QEMU.
- 86729 source entries/32-файловый patch восстановлены без fuzz/offsets;
  601 host rootfs entries/607CPIO,3recovery cases,45прежних signed packages,
  66ELF, decompressor6/handoff5/restart8 и границы RAM проверены.

Native device effects и QEMU key backend синтетические, физические MCU,
CCMP,DMA,RF не эмулируются. Нужны поиск C80-RAM38 и подключение одного
WPA2/DHCP клиента на устройстве. Один клиент,CCK/20MHz/MTU1400; AP restart
и смена канала в той же загрузке не поддерживаются. DMA pool668112 прежний.
Персональный архив и source members заморожены; аппаратный результат
будет записан отдельно без изменения исходников выпуска.
