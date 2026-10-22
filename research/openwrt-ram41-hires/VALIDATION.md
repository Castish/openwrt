# Проверка RAM41

Конфигурации физического и QEMU-ядер отличаются от RAM40 только HIGH_RES_TIMERS,
его зависимостями TICK_ONESHOT/SCHED_HRTICK, именем версии и путём initramfs.
HZ=100, 15 файлов C/headers драйверов и полный 32-файловый Linux-патч прежние.
В rootfs изменены метки SSID/версии и вызов диагностики в report; добавлен
статический ARM c80-timer-check без новой библиотеки. Пакеты/firmware прежние.

Свежие проверки:48QEMU WPA2/hostapd/cfg80211,13startup-removal,10timer cases
(5на неизменном родительском QEMU-ядре и5на новом,64nanosleep в каждом),
6ARMdecompressor/5handoff/8restart, полное восстановление86729source entries,
rootfs602host/608CPIO и3recovery cases,67ARMELF/45signed packages.
QEMU MemAvailable6592KiB. Адрес kernelentry40208000, конец физического образа
40b77678, QEMU40c777f8; оба до личного initrd40d00000.

Один и тот же диагностический ARM-бинарник на настоящем Linux в QEMU сообщает
clock_getres10мс против1нс; среднее nanosleep1мс —9,876813мс против1,597544мс.
Это проверка Linux/generic timers; она не моделирует физические MCU/DMA/CCMP/RF
и не измеряет задержку Wi-Fi. Объявленное разрешение1нс не является аппаратной
точностью или сроком пробуждения задачи. Аппаратная проверка RAM41 ожидается.

3871native ASan/UBSan и23OEMARM cases наследуются от RAM40 по совпадающим
исходникам, не перезапускались. Включённый Windows-сценарий байт-в-байт прежний.
Исходный аппаратный RAM40 baseline:5345/5345ping без потерь,TCP22,42ring wraps/
1token wrap,encrypted5383/5409,чистая остановка; это не результат нового ядра.
