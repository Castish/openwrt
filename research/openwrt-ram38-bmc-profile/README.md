# RAM38: заводской профиль BMC

**Аппаратный результат RAM38:** SSID виден, клиент дважды прошёл ассоциацию,
EAPOL_TX/RX2/2. Драйвер отклонил обновление ключа refused2; hostapd сообщил
GMK/GTK setup failed. PTK/authorization/encryptedIP0. До очистки raw beacon1129
через115,58секунды после GTK. Остановка чистая, DMAidle/MCUstopped,
inflight0; буферы после client TX сохраняются до reboot. Повторяемость видимости
ещё не проверена. Следующий опыт — [RAM39](../openwrt-ram39-gtk-init/).

RAM37 действительно работала на канале 1 / 2412 МГц, но сеть не появилась.
Все четыре сохранённых счётчика маяков показали 0, включая снимок через
246,90 секунды после GTK. Команды MCU завершились без ошибок, GTK/BMC были
установлены, остановка DMA/MCU и восстановление scheduler прошли чисто.
Смена канала не устранила наблюдаемый сбой. Клиент не подключался.

При проверке заводского кода обнаружено конкретное различие. Обычный запуск
AP формирует BMC с маской 0x2101; наш пакет использовал сокращённую 0x2001.
В нём отсутствовал блок tag 8, длина 8, flags 1 между BASIC и WTBL.
RAM38 добавляет этот блок: тело команды создания BMC теперь 252 байта вместо
244, число TLV — 3. Пакет побайтно совпадает с результатом заводского builder.
Команды удаления BMC, клиентской STA и ключей сохранены.

Канал 1, порядок запуска BMC/GTK, hostapd, калибровка, firmware, scheduler и
сохранение четырёх диагностических снимков прежние. Связь найденного различия
с отсутствием маяков ещё не подтверждена на устройстве. Успешная команда MCU
или проверка QEMU не доказывает передачу по радио.

## Загрузка через TFTP и SSH

В RAM37 уже получен Finished. Сохраните предыдущий manifest и payload-файлы.
В корень TFTP 192.168.0.3 скопируйте из нового архива:

- c80-openwrt-ram38-bmc-profile-zImage
- c80-openwrt-ram38-bmc-profile.dtb
- c80-openwrt-ram38-handoff.bin
- c80-auth.cpio

**Последним замените c80-start.txt.** Через LAN1 SSH выполните обычный reboot.
Прежний модифицированный U-Boot автоматически скачает и проверит файлы.
Новая запись NOR/U-Boot, UART и отключение питания не нужны. SSH:
root@192.168.0.1, пароль openwrt. Индивидуальные серверные ключи прежние.

После загрузки выполните по одной:

```sh
uname -r
c80-wifi start
c80-wifi diag
```

Ожидаемая версия: 6.12.113-c80-openwrt-ram38-bmc-profile.
Сеть **C80-RAM38**, канал 1, WPA2-PSK/CCMP, пароль **openwrt123**.
Обновите поиск Wi-Fi в течение 30 секунд. Если сеть появилась, подключите
один компьютер с автоматическими IPv4/DNS. DHCP выдаёт 192.168.2.2,
адрес AP — 192.168.2.1. В PowerShell:

```powershell
Find-NetRoute -RemoteIPAddress 192.168.2.1 | Format-List IPAddress,InterfaceAlias
ping -n 10 -w 1000 192.168.2.1
```

Маршрут должен выбрать физический Wi-Fi с источником 192.168.2.2. Через LAN1
соберите c80-wifi status и logread -e hostapd. Независимо от видимости сети
выполните c80-wifi stop, проверяйте status до Finished, затем c80-wifi diag и
c80-wifi report. Нужны оба diag, полный report и результат поиска/подключения.
Четвёртый снимок сохраняется до удаления GTK. Повторный start в той же
загрузке не поддерживается; следующий опыт выполняется после reboot.

## Проверка перед выпуском

3712 native ASan/UBSan cases: прежние 3700 и 12 новых BMC cases. Новые случаи
сравнивают настоящий producer с независимым OEM oracle, проверяют границы
252/28 байт через guard pages и отказ установки GTK при девяти видах ошибок
создания BMC. Прежние security, channel и beacon_diag suites также выполнены.

23 свежих OEM ARM cases: 13 security, 6 channel, 2 normal AP request и
2 BMC profile. Настоящий OEM конструктор запроса обычного AP выбирает 0x2101
для open/CCMP; настоящий STA builder добавляет ровно 8 байт при переходе с
0x2001 на 0x2101. OS и некоторые сторонние BSS helpers синтетические.

40 QEMU checks используют настоящие stock hostapd/cfg80211/OpenWrt:
канал 1, независимое WPA2-рукопожатие, неверный MIC, два подключения,
13 Linux DHCP/IP/TCP cases, pinned SSH password login и 32 настоящих ARM
report callbacks. Ещё 13 startup-removal checks проверяют отказ помощника
сообщать об успехе после удаления AP. MCU/CCMP/DMA/RF backend синтетический.

86729 исходных entries и полный 32-файловый Linux patch восстановлены без
fuzz/offset. Проверены 601 host rootfs entries / 607 CPIO entries, recovery,
45 прежних signed packages / 66 ELF, decompressor, handoff, restart и границы
RAM. Меняются только SSID и версия помощника в двух rootfs templates.
DMA pool — прежние 668112 байт; offsets и EMI reservation сохранены.

Ограничения: один клиент, 2.4 ГГц / CCK / 802.11b, 20 МГц, MTU 1400;
group→PTK unicast, GTK rekey отключён. Нет PMF/WPA3/5GHz/HT/VHT/multiclient,
full UCI wifi up, перезапуска AP и смены канала в той же загрузке.
Физическое подключение WPA2/CCMP пока не подтверждено. NOR остаётся MTD_ROM.
После любого client TX буферы сохраняются до reboot.

Сборка: source ../../activate.sh; bash build-kernel.sh; bash build-qemu.sh.
Source/build caches находятся отдельно в ../../caches/. restore-source.py и
restore-rootfs.py восстанавливают inputs. Полный Linux patch и разница
ram37-to-ram38.patch входят в архив. Скрипты сборки/проверки выполняют в новой
рабочей копии до выпуска. Выданный ZIP и его manifest members неизменяемы;
новые аппаратные результаты сохраняются отдельно.

Архив персональный: c80-auth.cpio содержит прежние индивидуальные SSH-ключи.
OEM firmware и прочие локальные inputs нужны для восстановления сборки.
ZIP/CPIO/private keys/OEM/calibration/raw logs не публикуются в Git и не
предназначены для другого устройства.

Публичные rootfs templates находятся в overrides/. Персональный SSH overlay,
OEM firmware и Linux tar подключаются локально; они не входят в этот Git.
Общие prerequisites: ../../docs/BUILD.md.
