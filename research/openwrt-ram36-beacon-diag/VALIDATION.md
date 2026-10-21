# RAM36: границы проверки

На аппаратуре владелец увидел C80-RAM36 и прислал live/stopped diag и полный
отчёт. Он явно не подключал клиент. WPA2-рукопожатие и шифрованный обмен
на плате остаются непроверенными.

Live diag вернул saved=7 во время AP; stopped diag — saved=f. Первые три
снимка сохранились без изменения, все четыре guard=0. Значения raw MIB_SDR0
по порядку:1/0/0/357. Последний снимок сделан до удаления ключей, GTK=1/BMC=1,
через36540054us после after_GTK_install (около356,84 периодов100TU).
Это согласуется с продолжающейся работой маяка после GTK и видимостью SSID.
Другие наблюдаемые MAC-регистры во всех четырёх снимках совпадают. MIB может
очищаться при чтении: число357 не является итогом всех передач или RF-захватом.

Один start/explicit stop, активное окно36566257us. После stop result/primary/
cleanup/critical=0, phase90;32/32/32 MCU commands,9reuses/0fault;63/63 totalTX.
Scheduler restored, DMA idle=1, MCU stopped=1, pools_retained=0. Клиентов,
auth/assoc/EAPOL, runtime management/data TX и encrypted traffic не было.
MemAvailable8180KiB, reboot требуется для нового старта; питание отключать
не требуется, flash_writes=0.

Причина изменения видимости RAM35/RAM36 не установлена. Диагностические
чтения/задержки и новое имя сети могли повлиять; изменение радио/ключевой
последовательности не вводилось. Следующий тест использует ту же RAM36 после
обычного reboot и проверяет один WPA2/DHCP клиент и физический Wi-Fi маршрут.

Исходный приватный отчёт:17598bytes, SHA256
251c1a1ced401debe1942c30f3b145b66e84785db282fac2e0ac27b79c38f0b3.
В Git записаны только обезличенные показатели, без сырых логов/адресов/ключей.

Программная проверка при выпуске:

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
Все четыре новых аппаратных снимка и видимость C80-RAM36 проверены в описанном
выше одном запуске. Длительность и повторяемость ещё не проверялись.
