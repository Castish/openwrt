# RAM37: проверка Wi-Fi на канале 1

На канале6 RAM36 один раз появилась в поиске Wi-Fi, но после обычного reboot
снова не была видна. В первом запуске pre-cleanup счётчик маяков показал357 за
36,54секунды после GTK. Во втором все четыре снимка показали0, включая снимок
через241,50секунды после GTK. В обоих случаях AP активна, команды приняты,
GTK/BMC установлены, остановка MCU/DMA чистая. Клиент не подключался.
Причина непостоянной видимости ещё не установлена.

По запросу владельца RAM37 переводит эту проверку на **канал1 /2412МГц**.
Один профиль согласован между cfg80211, проверкой DS IE маяка, hostapd,
командами MCU CHANNEL/PATH и отчётами. Самостоятельно менять только строку
channel в старой RAM36 нельзя: драйвер той версии разрешает только канал6.
Канал выбирается до запуска, переключение работающего AP не реализовано.

Новая c80_radio.h задаёт профиль1 для физического и QEMU адаптеров. Core
принимает только1/6; ноль оставлен как прежний канал6 для регрессионных fixtures.
Неподдерживаемые значения отклоняются до MMIO. В заводских CHANNEL/PATH
пакетах меняются только primary/center channel bytes, поля мощности прежние.
Legacy beacon DS IE также следует выбранному каналу. WPA2, scheduler, ключи,
calibration, firmware, CPU-only beacon_diag и lifecycle-порядок RAM36 сохранены.
Это проверка другой частоты, не обещание исправления видимости или WPA2.

## Загрузка через прежний TFTP и SSH

Текущая RAM36 уже Finished с чистой остановкой. Сохраните предыдущий manifest
и payload-файлы. В корень TFTP192.168.0.3 скопируйте из этого архива:

- c80-openwrt-ram37-channel1-zImage
- c80-openwrt-ram37-channel1.dtb
- c80-openwrt-ram37-handoff.bin
- c80-auth.cpio

**Последним замените c80-start.txt.** Выполните обычный reboot через LAN1 SSH.
Модифицированный U-Boot автоматически скачает и проверит payload. Новая запись
NOR/U-Boot, UART и отключение питания не нужны. SSH root@192.168.0.1,
пароль openwrt, индивидуальные серверные ключи прежние.

После загрузки выполните по одной:

```sh
uname -r
c80-wifi start
c80-wifi diag
```

Версия должна быть6.12.113-c80-openwrt-ram37-channel1. Сеть **C80-RAM37**,
WPA2-PSK/CCMP пароль **openwrt123**, канал1. Обновите поиск в течение30секунд.
Если сеть видна, подключите один компьютер с автоматическими IPv4/DNS:
DHCP192.168.2.2, AP192.168.2.1. В PowerShell:

```powershell
Find-NetRoute -RemoteIPAddress 192.168.2.1 | Format-List IPAddress,InterfaceAlias
ping -n 10 -w 1000 192.168.2.1
```

Маршрут должен выбрать физический Wi-Fi с источником192.168.2.2; ранее VPN
создавал ложноположительный ping. Через LAN1 соберите c80-wifi status и
logread -e hostapd. Затем c80-wifi stop, status до Finished, c80-wifi diag и
c80-wifi report. Нужны оба diag, полный report и результат поиска/подключения.
Даже при невидимой сети остановка сохранит четвёртый снимок до удаления GTK.
Повторный start в той же загрузке не поддерживается; следующий опыт после reboot.

## Программная проверка

3700 native ASan/UBSan cases: прежние3624 и76 новых selected-channel cases.
Новые проверки исполняют настоящий полный core для1/6 с независимыми OEM
пакетами, success/reject/timeout paths, legacy DS IE и refusal до MMIO.
19 свежих OEM ARM cases:13 прежних security и6 новых CHANNEL/PATH/wrapper
для1/6. Синтетические аргументы/OS и внешние RF helpers, физического радио нет.

40 QEMU checks настоящих stock hostapd/cfg80211/OpenWrt, включая объявление
только2412MHz, отказ старого канала6, AP наканале1, независимое WPA2-рукопожатие,
неправильный MIC, два авторизованных подключения,13 Linux DHCP/IP/TCP cases,
pinned SSH password login и32 настоящих ARM report callbacks. Ещё13 checks
инъекции пустой hostapd-конфигурации проверяют lifecycle-защиту.
QEMU key backend синтетический: физические MCU/CCMP/DMA/RF не эмулируются.

86729 исходных entries/32-файловый Linux patch восстановлены без fuzz/offset;
601 host rootfs entries,45 прежних signed packages/66ELF сверены, проверены
source/rootfs recovery, decompressor, handoff, restart и размещение ниже auth.
DMA pool668112bytes, offsets и EMI reservation прежние. Базовые приватные
factory/source inputs локальные; их нет в публичном Git. Все build/proof
scripts нужно выполнять в новой рабочей копии до выпуска: выданный ZIP и его
manifest members неизменяемы. Новые аппаратные результаты идут отдельно.

Ограничения: один клиент,2.4GHz/CCK/802.11b,20MHz,MTU1400; group→PTK unicast,
GTK rekey отключён. Нет PMF/WPA3/5GHz/HT/VHT/multiclient/full UCI wifi up,
перезапуска AP или смены канала в той же загрузке. NOR остаётся MTD_ROM.
После любого client TX буферы сохраняются до reboot.

Сборка: source ../../activate.sh; bash build-kernel.sh; bash build-qemu.sh.
Исходный cache и build outputs находятся отдельно в ../../caches/, потому что
в /tmp мало места. restore-source.py/restore-rootfs.py восстанавливают inputs;
полный32-файловый Linux patch и ram36-to-ram37.patch входят в архив.

Архив персональный: прежние индивидуальные SSH-ключи в c80-auth.cpio, OEM
firmware для локальной сборки. ZIP/CPIO/privatekeys/OEM/calibration/rawlogs
не публикуются в Git и не предназначены для чужого устройства.

Публичные rootfs templates находятся в overrides/. Персональный SSH overlay,
OEM firmware и Linux tar подключаются локально; они не входят в этот Git.
Общие prerequisites: ../../docs/BUILD.md.
