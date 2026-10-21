# RAM40: управляющие кадры при повторном WPA2-подключении

**Аппаратная проверка RAM40 пройдена для WPA2-переподключения:** один клиент
трижды завершил WPA2 handshake при одном запуске AP — два повторных подключения.
Драйвер принял три нешифрованных deauth с признаком CCMP/CipherMis;
первый RXD2=e0044001, FC=00c0. Прежний фильтр отверг бы именно такой кадр.
Ошибок ключей/PN/DMA нет: EAPOL6/6, encryptedTX/RX10/49,53/53/53команды,
20/20завершённых runtimeTX. Остановка чистая, DMAidle/MCUstopped,
inflight0, MemAvailable7760KiB. Пользователь сообщил, что ping не выполнял;
DHCP-аренда, маршрут и TCP отдельно ещё не подтверждены.

В RAM39 первый WPA2 handshake физически завершился: GTK_refreshes1,
PTK/authorized1, EAPOL2/2 и encryptedTX/RX7/29. После отключения клиента
повторное подключение не прошло. Auth/assoc остались1/1, deauth/disassoc0;
bad вырос34→206. Остановка прошла без ошибок, DMA/MCU остановлены,
все TX завершены, MemAvailable7744KiB. DHCP-аренда, маршрут, ping и TCP
для этого WPA2-подключения владельцем ещё не подтверждены.

Старый общий RX-фильтр требует SecMode0 и отсутствия CipherMis также для
нешифрованных управляющих кадров. При установленном PTK аппаратный WCID
может указывать CCMP для обычного auth/deauth/disassoc того же клиента.
Такие кадры не доходят до автомата сессии. Это воспроизведено настоящим
кодом RAM39 на синтетическом RXD. Точные RXD-флаги исходной неудачи RAM39 не были сохранены. В RAM40 уже
измерен обычный deauth с CCMP/CipherMis, принятый новым исключением;
в этой же загрузке успешно прошли два повторных WPA2-подключения.

RAM40 допускает SecMode0/4 и CipherMis только для обычных lifecycle management
кадров прежнего клиента, адресованных нашему AP/BSSID, в активной WPA2-сессии
с PTK и живым STA. Protected/Order, фрагментация, FCS, ICV/MIC и ошибки
длины/перевода заголовка этим исключением не обходятся. Алгоритм auth,
RSN/body validation и требования к шифрованным данным/PN прежние.
Рабочий поток дожидается завершения TX, удаляет старый PTK и STA и только
потом готовит новый ответ auth. Ключи не сбрасываются при чтении отчёта.

Новый раздел RX_gate в mgmt/report сохраняет причины отбрасывания,
режимы шифра, типы адресованных lifecycle-кадров и первые RXD2/FC без
пакетов, MAC-адресов, ключей или PN. Это позволит проверить гипотезу,
если повторное подключение снова не пройдёт. Ошибка имени ядра в helper
также исправлена; версия guard сверяется с фактическим kernel.release.

## Загрузка через прежний автоматический U-Boot

После Finished в RAM39 скопируйте в корень TFTP192.168.0.3:

- c80-openwrt-ram40-rx-status-zImage
- c80-openwrt-ram40-rx-status.dtb
- c80-openwrt-ram40-handoff.bin
- c80-auth.cpio

Последним замените c80-start.txt и выполните обычный reboot через LAN1 SSH.
Идентичность SSH сохранена: root@192.168.0.1, пароль openwrt.
Новая запись NOR/U-Boot, UART и отключение питания не нужны.

После загрузки:

```sh
uname -r
c80-wifi start
```

Ожидается6.12.113-c80-openwrt-ram40-rx-status. Подключите один компьютер к
**C80-RAM40**, пароль **openwrt123**, IPv4/DNS автоматически.
Сначала до отключения клиента проверьте в PowerShell:

```powershell
Find-NetRoute -RemoteIPAddress 192.168.2.1 | Format-List IPAddress,InterfaceAlias
ping -n 10 -w 1000 192.168.2.1
```

Маршрут должен выбрать физический Wi-Fi и источник192.168.2.2.
Затем один раз отключите Wi-Fi на клиенте и подключитесь повторно;
при успехе повторите ping. Через LAN1 SSH сохраните c80-wifi status и
logread -e hostapd после попытки. Выполните c80-wifi stop, дождитесь Finished
в c80-wifi status и пришлите полный c80-wifi report. Раздел mgmt уже включён.
При неудаче также нужен report; не повторяйте start в той же загрузке.

## Проверки и пределы

3871 свежий native ASan/UBSan case:3753 прежних и118 новых RX status cases.
Новые проверки проходят через настоящий RX0/parser/session/key код:
16режимов и CM, ошибки статуса, чужой peer/BSSID, Protected/Order/fragment,
проверка auth/reason/RSN,41guard-page длина, ожидание inflight и подтверждённое
удаление старого PTK/STA перед новым auth. Старый RAM39 RX gate отдельно
воспроизводит отказ. Эффекты RXD/MCU/DMA синтетические.

48 QEMU stock hostapd/cfg80211 checks сохраняют два программных WPA2 handshake,
неверный MIC, независимый PMK/PTK/MIC/AES unwrap,13Linux DHCP/IP/TCP checks,
pinned SSH и32actual ARM report callback cases. Пять новых проверок исполняют
настоящий helper guard; positive version fixture останавливается до MCU.
Ещё13startup-removal checks проверяют завершение AP. QEMU не эмулирует
физические MCU/DMA/CCMP/RF и не доказывает аппаратное переподключение.

Полный32-файловый Linux patch и86729source entries восстановлены без
fuzz/offset; CPIO607/host601,3recovery cases,45прежних signed packages/66ELF,
decompressor6/handoff5/restart8 и границы RAM проверены. DMApool668112B
прежний. OEM23ARM checks наследуются от RAM39 по неизменным конструкторам
key/BMC/channel; повторно эти трассы не запускались.

Ограничения: один клиент,2.4GHz/CCK/802.11b/20MHz/канал1/MTU1400,
group→PTK unicast, периодический rekey отключён. Перезапуск AP в той же
загрузке, WPA3/PMF/5GHz/HT/VHT/multiclient/fullUCI не реализованы.
Архив персональный, содержит серверные ключи/OEM inputs; в публичном Git
сохраняются только наши исходники и обезличенные результаты.

Публичные rootfs templates: overrides/. Для локальной сборки нужны персональные/OEM inputs; они не входят в Git. См. ../../docs/BUILD.md.
