# RAM36: границы проверки

На аппаратуре RAM36 ещё не проверена. Это диагностика пропавшего SSID RAM35,
а не подтверждённое исправление передачи маяка или WPA2.

- 3624 заново выполненных native ASan/UBSan cases, включая 48 новых случаев
  настоящего shared core/key producer с синтетическим MMIO и OEM byte oracle.
- 13 заново выполненных OEM ARM builder cases. Radio/key/beacon command bytes
  прежние; добавлены только наблюдения CPU и чтения уже известных MAC-регистров.
- 32 проверки настоящих ARM show/publish callbacks в QEMU с run-mutex и без
  него: legacy -EBUSY, live snapshot без ожидания, сохранение значений публикации.
- 37 QEMU integration checks с настоящим stock hostapd/cfg80211/OpenWrt,
  независимой проверкой WPA2 PMK/PTK/MIC/AES unwrap, неверным MIC, двумя
  авторизациями, 13 Linux DHCP/IP/TCP cases и pinned SSH password login.
- 13 дополнительных startup-removal checks, сохранённая lifecycle-библиотека.
- 86728 source entries и 601 rootfs entries восстановлены и сверены. Полный
  Linux patch31 файлов без fuzz/offsets; layout/decompressor/handoff/restart
  проверены. 45 прежних signed packages, 66 ELF, DMA pool668112B и offsets прежние.

Имя сети изменено с C80-RAM35 на C80-RAM36. Поэтому буквальные байты SSID в
beacon payload отличаются; неизменны конструктор и wire format при одинаковых
входах, а не весь шаблон с новым именем. Исходный PROVENANCE field
radio_key_and_beacon_command_bytes_unchanged следует читать в этом смысле.

MIB может очищаться при диагностическом захвате: raw значения нельзя считать
итогом передач. sysfs beacon_diag читает только согласованную CPU-копию.
QEMU использует synthetic key backend и не исполняет физические MCU/CCMP/RF/DMA.
Предыдущая ошибка чтения legacy-файлов live подтверждена кодом и аппаратным
ожиданием mutex; восстановление вторым SSH/stop прошло без отключения питания.
Все четыре новых аппаратных снимка и видимость C80-RAM36 требуют проверки.
