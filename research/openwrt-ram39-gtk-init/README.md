# RAM39: обновление GTK при первом клиенте

В RAM38 владелец увидел защищённую C80-RAM38. Клиент дважды прошёл ассоциацию,
AP приняла и отправила по два EAPOL, но hostapd сообщил key addition failed /
GMK/GTK setup failed. В драйвере refused=2, PTK и авторизации нет. До очистки
счётчик маяков показал1129 через115,58секунды после GTK. Остановка чистая,
DMAidle/MCUstopped, TX завершены; буферы после client TX сохранены до reboot.
Это подтверждает видимость и ассоциацию в данном запуске; повторяемость
видимости и завершённое подключение WPA2 ещё не подтверждены.

Штатный hostapd заново создаёт GMK/GTK при первом клиенте даже при отключённом
периодическом rekey. RAM38 запрещала любой отличающийся установленный ключ.
Настоящий код RAM38 воспроизвёл этот отказ в тесте. RAM39 разрешает замену GTK
до установки PTK и авторизации: две заводские команды удаления должны получить
ACK и завершить DMA, затем отправляется установка нового GTK. Ошибка на любом
шаге прерывает запуск. При смене GTK не пересоздаётся BMC, маяки не отключаются.

Одинаковые ключи по-прежнему пропускаются без переустановки и сброса PN.
Изменённый активный PTK и GTK при имеющемся PTK/авторизации отклоняются.
Ключи, nonce и PN в отчёт не попадают. Новое поле GTK_refreshes считает успешные
замены. Первые три снимка beacon_diag сохраняют первоначальное состояние;
четвёртый снимается до финальной очистки с текущим ключом.

Канал1/2412MHz, BMC252байта с tag8 из RAM38, stock hostapd, firmware,
калибровка, scheduler, SSH и формат TFTP прежние. QEMU теперь использует ту же
политику add/reinstall, что и физический core; ранее тестовый backend принимал
любые ключи и не обнаруживал этот отказ. Команды MCU/DMA в нём синтетические.

## Загрузка без UART

В RAM38 уже получен Finished. В корень TFTP192.168.0.3 скопируйте:

- c80-openwrt-ram39-gtk-init-zImage
- c80-openwrt-ram39-gtk-init.dtb
- c80-openwrt-ram39-handoff.bin
- c80-auth.cpio

Последним замените c80-start.txt. Выполните обычный reboot через LAN1 SSH.
Прежний U-Boot загрузит RAM39 автоматически. Новая запись NOR/U-Boot и
отключение питания не нужны. SSH root@192.168.0.1, пароль openwrt,
индивидуальные серверные ключи сохранены.

После загрузки выполните по одной:

```sh
uname -r
c80-wifi start
c80-wifi diag
```

Ожидаемая версия6.12.113-c80-openwrt-ram39-gtk-init. Ищите C80-RAM39,
канал1, WPA2-PSK/CCMP, пароль openwrt123. Подключите один компьютер с
автоматическими IPv4/DNS. AP192.168.2.1, DHCP192.168.2.2.
В PowerShell после подключения:

```powershell
Find-NetRoute -RemoteIPAddress 192.168.2.1 | Format-List IPAddress,InterfaceAlias
ping -n 10 -w 1000 192.168.2.1
Test-NetConnection 192.168.2.1 -Port 22
```

Маршрут должен выбрать физический Wi-Fi с источником192.168.2.2, а не VPN.
Через LAN1 SSH соберите c80-wifi status и logread -e hostapd. Затем выполните
c80-wifi stop, status до Finished, c80-wifi diag и c80-wifi report.
Пришлите полный report, оба diag и результат подключения/проверок Windows.
При неудаче повторные попытки допустимы до stop; новый start в той же загрузке
не поддерживается. Следующий опыт выполняется после обычного reboot.

## Проверка

3753 native ASan/UBSan cases:3712 прежних и41 новый GTK refresh case. Они
исполняют настоящий core: смена ключа/ID до PTK, ожидание inflight TX,
идемпотентность/PN, отказ при PTK/авторизации, сохранение снимков и27ошибок
на трёх командах delete/delete/install. Отдельный запуск настоящего RAM38 core
воспроизводит старый отказ. Это синтетические MCU/DMA/RF effects.

23 свежих OEM ARM cases проверяют прежние key/BMC/radio пакеты. Изменений
форматов команд нет. Проверен полный32-файловый Linux patch и восстановление
86729source entries без fuzz/offsets,601host rootfs entries/607CPIO,
3recovery cases,45прежних signed packages/66ELF, decompressor/handoff/restart
и границы RAM. DMApool668112B и его offsets прежние.

43 QEMU stock hostapd/cfg80211/OpenWrt checks включают новую проверку
первоначального GTK, реального first-station refresh через общую политику и
отсутствия GMK/GTK setup failed. Сохраняются неверный MIC, два авторизованных
подключения,13LinuxDHCP/IP/TCP checks,pinnedSSH и32actualARMreportcallbacks.
Ещё13startup-removal checks проверяют корректное завершение AP. Физические
MCU/CCMP/DMA/RF в QEMU не эмулируются; аппаратный тест RAM39 ожидается.

Один клиент,2.4GHz/CCK/802.11b/20MHz/MTU1400; group→PTK unicast, периодический
GTK rekey отключён, GTK не используется для TX. Нет WPA3/PMF/5GHz/HT/VHT,
нескольких клиентов, полного multicast/UCI wifi up, смены канала и AP restart
в той же загрузке. Первый успешный WPA2/IP обмен на физическом роутере
ещё требуется подтвердить. NOR остаётся MTD_ROM read-only.

Сборка: source ../../activate.sh; bash build-kernel.sh; bash build-qemu.sh.
Source/build caches находятся отдельно в ../../caches/. Для OEM ARM трасс
дополнительно нужны Unicorn из ../ram-probe/tools и локальная factory image.
restore-source.py/restore-rootfs.py восстанавливают проверенные inputs.
Выполняйте mutating build/proof/package scripts в отдельной рабочей копии до
выпуска. Выданные ZIP и manifest members неизменяемы; новые hardware-* и
STATUS записи сохраняются отдельно. Полный patch и ram38-to-ram39.patch в архиве.

Персональный архив содержит c80-auth.cpio с прежними индивидуальными SSH-ключами.
ZIP/CPIO/SSH private keys/OEM/calibration/raw logs не публикуются в Git.

Публичные rootfs templates находятся в overrides/. Персональный SSH overlay,
OEM firmware и Linux tar подключаются локально; они не входят в этот Git.
Общие prerequisites: ../../docs/BUILD.md.
