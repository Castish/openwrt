# Структура и сборка

`research/<этап>/` содержит исходный снимок: собственный C/ARM-код, полные
патчи Linux, конфигурацию, скрипты сборки и проверки. SOURCE-MANIFEST.json
содержит SHA256 исходников; SNAPSHOT.json — отобранные сведения о выпуске.
Публичные исходники побайтно совпадают с сохранёнными оригиналами.

Исторические скрипты рассчитаны на использованное облачное окружение:
Debian13, GCC14.2 arm-linux-gnueabi (мягкая float ABI), binutils2.44,
Linux6.12.113, OpenWrt25.12.5 arm_cortex-a7, jobs4. Точные версии пакетов
сохранены в `openwrt-packages.json` и `packages.lock` соответствующего этапа.
Полного checkout upstream Linux/OpenWrt и бинарных toolchain в Git нет.

## Исходный Linux

Подписанный оригинальный Linux:
https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.12.113.tar.xz
https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.12.113.tar.sign
SHA256 архива:
`e09b6727e5c521253f0d41694900b9c38fb7604db7d35238a8197aa9f7de2428`.

Для этапов с `linux-mt7626-bringup.patch` распакуйте этот архив в отдельный
рабочий каталог и примените полный патч `patch --fuzz=0 -p1`. В этих патчах
содержится полный соответствующий код платы и драйверов, без закрытых blobs.
Исходный release/build должен собираться в отдельном каталоге; сохраняйте
родительские версии неизменными. Нельзя использовать hardlink-копии Linux
при правке драйверов: изменится и родительский исходник.

## Пользовательская система и локальные входы

OpenWrt userspace получают из официальных подписанных APK-пакетов; пример
первоначальной сборки — `research/openwrt-ram1/build-rootfs.sh` и
`prepare-rootfs.py`, публичные URL/списки пакетов сохранены рядом. Их исходные
пути к ImageBuilder, инструментам и кэшу нужно настроить под своё окружение.
Исторические restore/package-скрипты могут ссылаться на личные ZIP/CPIO,
которые намеренно отсутствуют в публичном Git. Переносимость каждого старого
полного образа вне исходной облачной среды отдельно не проверялась.

Шесть OEM firmware-файлов извлекаются локально из собственной заводской
прошивки Archer C80(RU)_V1_240812; имена, размеры и хеши приведены в
FIRMWARE-SOURCES.json. Для ARM-трассировок нужен собственный локальный TPOS/
дамп. Калибровка RADIO читается с устройства; её нельзя заменять чужой.
Некоторые ранние пробы и guard-значения привязаны к исследованной плате и
точному заводскому образу — это записано в их коде и проверках.

`make-initramfs-list.py`, `prepare-kernel.py`, `minimal.config` и
`build-kernel.sh` показывают состав ядра и RAM-rootfs каждой версии.
ARM-модели/QEMU проверяют программные контракты, а не работу C80 RF/DMA.
Проверки с бинарными OEM-оракулами требуют локальных входов, генерируемых
`trace-stock-*.py`/фикстурами из своей прошивки; сами бинарные оракулы не
входят в публикацию. Это не самодостаточный upstream OpenWrt build target.

## Сеть загрузки и SSH

Рабочий native U-Boot проверяет `c80-start.txt` на TFTP192.168.0.3,
собственный адрес192.168.0.1, компьютер в LAN1. C80SCRIPT1 поддерживает
проверяемые `load ADDRESS FILE HEXBYTES HEXCRC32`, `go ADDRESS`, `end`.
Образы исполняются из RAM; отдельного install/sysupgrade формата OpenWrt нет.

SSH-конфигурация генерируется индивидуально локально. Нельзя публиковать
`c80-auth.cpio` или использовать серверные ключи другого устройства. Шаблон
`ssh-identity-v1/make-auth.py` генерирует новые ключи для каждой новой
конфигурации и сохраняет уже созданные при повторной сборке. Пароль шаблона
для тестовой RAM-системы — openwrt; персональные key/shadow-файлы сюда не входят.

## Архив подготовки среды

[cloud-host-setup](../research/cloud-host-setup/) сохраняет install/activate/verify
и список Debian-пакетов исходной облачной среды. Скрипт install.sh готовит
только host tools в /workspace/.openwrt-onboarding, не клонирует OpenWrt и не
меняет checkout. Дополнительные cross-toolchain/QEMU/Unicorn зависимости
поздних этапов задаются соответствующими исследовательскими скриптами.
[inspect-firmware.py](../research/wifi-bringup/inspect-firmware.py) описывает
структуру локально предоставленного OEM Wi-Fi образа без его распространения.

## RAM32 cfg80211

Исходники находятся в research/openwrt-ram32-cfg80211. Каталог overrides/
содержит собственные c80-wifi, c80-hostapd и конфигурационные шаблоны;
копируйте их по тем же относительным путям в локально собранный rootfs.
Добавлены подписанные hostapd-basic-mbedtls, hostapd-common, libmbedtls21,
iw, wireless-regdb, wifi-scripts и ucode-mod-nl80211/rtnl/digest. Точные версии
перечислены в packages.lock. Шесть OEM firmware-файлов предоставляются локально.

CFG80211 включён, MAC80211 не требуется: собственный драйвер использует
device SME. Физическое ядро не включает QEMU-only C80_NET_SELFTEST.
Архив полного патча содержит25 файлов; start_ap ждёт фактического включения
beacon в MCU, stop_ap — завершения прежней процедуры DMA/MCU cleanup.
Персональный auth initramfs размещён по40d00000; тот же адрес требуется
в manifest и chosen/initrd DTB. Создавайте собственные ключи локально.

Образ по-прежнему загружается из RAM. Полной UCI wifi up интеграции, WPA2
и готового flash/sysupgrade-формата эта версия не предоставляет.

## RAM33 reconnect

research/openwrt-ram33-reconnect сохраняет пакеты и SSH-overlay RAM32.
Скопируйте собственные rootfs overrides/ в локальную rootfs; полный Linux-патч
теперь содержит26 файлов. Добавлены c80_session_core.h и два1152-байтовых
DMA command buffer; прежние смещения DMA объектов сохранены, pool вырос
на2320 байт до668112. Native session verifier проверяет действительные
функции с синтетическими device effects, но не весь c80_run boot/teardown.
build-qemu.sh строит отдельный software-peer kernel; он не предназначен
для роутера. В физическом ядре C80_NET_SELFTEST отключён.

Новый AP SSID — C80-RAM33. Копируйте четыре TFTP-файла, затем manifest последним;
установленный native U-Boot скачает их после reboot. Auth CPIO по40d00000
сохраняется. Клиент переподключается до stop, AP start выполняется один раз.
Счётчики живой сессии доступны в /sys/kernel/c80_wifi/session без run-mutex.
Архив персональных образов и сырые тестовые логи в публичный Git не входят.

## RAM34 WPA2-PSK/CCMP

research/openwrt-ram34-wpa2/ содержит собственные исходники и полный31-файловый
Linux6.12.113 патч. Добавлены c80_security_types/parse/core.h, c80_key_linux.h
и c80_rsn.h. CPU mailbox cfg80211 передаёт операции в единственный MCU-поток;
ACK и DDONE ограничивают повторное использование/очистку key DMA payload.
Пакеты и668112-байтовый DMA pool прежние. Одинаковый ключ не переустанавливается.

verify-all-native.sh строит/исполняет native suites; для protocol oracles нужны
сохранённые proof JSON предыдущих этапов и локальная factory image для новых
ARM трасс. Образы/JSON evidence остаются в личном рабочем архиве. Для QEMU
verify-qemu-wpa2.py дополнительно нужен Python cryptography; он выполняет
настоящий hostapd handshake при синтетическом key-install backend. C80_NET_SELFTEST
выключен в физическом ядре. Старые Linux/runtime/toolchain prerequisites
сохраняются. Новая rootfs конфигурация находится в overrides/.

Развёртывание в тестовой среде: четыре личных TFTP-файла, c80-start.txt последним,
обычный reboot через LAN1 SSH. U-Boot не перепрограммируется. Wi-Fi тестовый
пароль openwrt123, root-пароль прежний; серверные ключи не меняются. На плате
нужен первый WPA2/DHCP/ping/reconnect/stop тест. Не используйте QEMU kernel
на роутере и не публикуйте персональные CPIO/ключи/OEM firmware.

## RAM35 startup helper

research/openwrt-ram35-netup/ сохраняет Linux/C/ASM и пакеты RAM34. Добавлена
библиотека c80_wifi_lifecycle.sh (в rootfs usr/libexec/), которую одинаково
исполняют helper и QEMU regression. Она поднимает wireless netdev до AP,
вызывает прямой ubus interface up без общего reload и проверяет состояние.
rootfs diff — ram34-to-ram35-rootfs.patch, полный Linux-патч прежний31 файл.
Свежие verify-qemu-wpa2.py и verify-qemu-startup-removal.py проходят36 и13
проверок соответственно.32 native inputs совпадают с исходниками проверенных
3576 cases RAM34. Для новой сборки нужны все7 overrides, включая библиотеку.
TFTP deployment прежний,SSID C80-RAM35/PSKopenwrt123. Нового U-Boot/NOR write
не требуется. Персональная SSH идентичность и root-пароль сохраняются.

## RAM36 beacon/key snapshots

research/openwrt-ram36-beacon-diag/ добавляет c80-wifi diag и saved CPU snapshots.
Скопируйте семь templates из overrides/ в rootfs. Персональный SSH overlay,
OEM blobs и Linux archive подключаются локально. verify-all-native.sh включает
48 новых beacon-diag cases и summarize-native.py. QEMU-only report-lock test
собран в c80_mcu_transport.c и вызывается до /init; физическое ядро его не имеет.
Полный31-файловый Linux patch и ram35-to-ram36.patch фиксируют исходные изменения.
Не запускайте mutating build/package scripts поверх выданного frozen ZIP.
TFTP deployment прежний: четыре payload-файла, c80-start.txt последним, reboot.
Проверка: start, diag, поиск C80-RAM36, stop, Finished, diag и report.

## RAM37: канал1

Снимок research/openwrt-ram37-channel1/ добавляет c80_radio.h, один профиль1
в физическом и QEMU адаптерах, OEM channel/path trace и76 native cases.
Полный Linux patch теперь32файла; build/source caches отдельно в ../../caches/
из-за нехватки места /tmp.3700 native,40 QEMU WPA2,13 startup-removal,
19 OEM ARM cases связаны с конкретными исходниками и kernel artifacts.
Публичные overrides/ заменяют только локальные templates; OEM/SSH inputs
по-прежнему нужны локально. Выданный ZIP не пересобирается поверх выпуска.

## RAM38: BMC normal AP profile

research/openwrt-ram38-bmc-profile/ изменяет только BMC create в shared core:
252байта, TLVs0/8/13, tag8flags1; delete28/peer244/key52 и порядок прежние.
trace-normal-ap-request.py и trace-bmc-profile.py исполняют OEM ARM constructor
и builder с локальной factory image. Собственные native tests проверяют OEM
байтовый oracle, guard pages252/28 и MCU failures; все3712cases выполнены.
Полный Linux patch32файла, ram37-to-ram38.patch и7rootfs overrides включены.
Профиль канала1 сохраняется.23OEM ARM/40QEMU/13startup-removal проверены,
но физические CCMP/DMA/MCU/RF в этих тестах не эмулируются.
Копируйте4новых личных TFTP payload, manifest последним, обычный SSH reboot.
Нового U-Boot/NOR write нет. Персональные CPIO/ключи/OEM inputs остаются локально.

## RAM39: initial client GTK refresh

research/openwrt-ram39-gtk-init/ сохраняет BMC252/tag8 и канал1. Общая политика
key add/reinstall в c80_security_types.h используется настоящим MCU core и
QEMU backend. До PTK/авторизации GTK refresh выполняет delete/delete/install,
ACK+DDONE на каждом шаге. Изменённый активный PTK/GTK rekey по-прежнему запрещён.
verify-gtk-refresh.sh исполняет текущий core и старый RAM38 baseline,41новыйcase.
Полный Linux patch32файла, ram38-to-ram39.patch,3753native/23OEMARM/43QEMU/
13startup-removal checks и прежние7overrides. Локальные OEM/SSH inputs нужны
для сборки. Копируйте4личныхpayloads, c80-start.txt последним, SSHreboot.

## Helper guard fix1

В исходном RAM39 helper ожидал неверный суффикс bmc-profile. Отдельный снимок ram39-helper-guard-fix исправляет guard через внешний 8KiB CPIO; только initrd-end меняется в DTB. Старый ZIP и ядро неизменны. Следующие сборки должны сравнивать ожидаемое имя helper с фактическим build/include/config/kernel.release и исполнять guard в QEMU с ограниченным version fixture до запуска MCU.

## RAM40: RX management status trial

Полный Linux patch32файла, ram39-to-ram40.patch, verify-management-status.sh и verify-artifacts.py связывают новые RX правила, 118новых/3871freshnative cases и exact kernel/helper version. QEMU48checks (включая5actualhelperguards),13removalchecks; подлинные RF/MCU/CCMP эффекты не эмулируются. Диагностика в mgmt включена в helper report. Персональный комплект загружается прежним autoTFTP через четыре payloads и c80-start.txt последним.

## RAM41: high-resolution timer trial

research/openwrt-ram41-hires/ содержит прежний полный32-файловый Linux-патч
и исходники драйверов RAM40. minimal.config включает HIGH_RES_TIMERS при
HZ100; обе конфигурации дополнительно выбирают TICK_ONESHOT/SCHED_HRTICK.
build-kernel.sh собирает c80-timer-check до генерации initramfs. Helper
использует ARM EABI clock_getres/clock_gettime/nanosleep, не имеет новой libc
и не обращается к периферии. verify-qemu-timers.py проверяет тот же бинарник
на неизменном родительском ядре (--parent) и новом ядре. QEMU-запуски должны
выполняться последовательно: используют один локальный порт40223.
verify-artifacts.py отдельно проверяет неизменность15C/header файлов,
унаследованные3871native/23OEMARM и свежие48WPA2/13startup-removal/10timer
проверок. Физический CPIO608entries, QEMU добавляет только прежний packet peer.
Выданный ZIP персональный; c80-auth.cpio сохраняет ключи конкретного владельца.
