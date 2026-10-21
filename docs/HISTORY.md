# История порта

До Git сохранились исходные снимки, тесты и личные архивы. Здесь они импортируются отдельными новыми коммитами; у каждого этапа свой тег.
| Этап | Содержание | Исходных файлов |
| --- | --- | ---: |
| [ram-probe](../research/ram-probe/) | Исполнение ARM-кода в RAM | 4 |
| [readonly-diag](../research/readonly-diag/) | CPU/CRC и чтение tail flash | 5 |
| [linux-bringup](../research/linux-bringup/) | Первое Linux-ядро | 12 |
| [linux-flash-backup](../research/linux-flash-backup/) | Read-only NOR и UART backup | 14 |
| [linux-ethernet-ram3](../research/linux-ethernet-ram3/) | linux ethernet ram3 | 19 |
| [ethernet-irq-probe](../research/ethernet-irq-probe/) | ethernet irq probe | 5 |
| [ethernet-irq-probe-v2](../research/ethernet-irq-probe-v2/) | ethernet irq probe v2 | 6 |
| [linux-ethernet-ram4](../research/linux-ethernet-ram4/) | linux ethernet ram4 | 20 |
| [switch-mdio-probe](../research/switch-mdio-probe/) | switch mdio probe | 6 |
| [switch-mdio-probe-v2](../research/switch-mdio-probe-v2/) | switch mdio probe v2 | 5 |
| [linux-ethernet-ram5](../research/linux-ethernet-ram5/) | linux ethernet ram5 | 26 |
| [linux-ethernet-ram6](../research/linux-ethernet-ram6/) | linux ethernet ram6 | 26 |
| [linux-ethernet-ram7](../research/linux-ethernet-ram7/) | linux ethernet ram7 | 32 |
| [linux-ethernet-ram8](../research/linux-ethernet-ram8/) | linux ethernet ram8 | 33 |
| [linux-ethernet-ram9](../research/linux-ethernet-ram9/) | linux ethernet ram9 | 33 |
| [openwrt-wifi-emi](../research/openwrt-wifi-emi/) | openwrt wifi emi | 13 |
| [connsys-id-probe](../research/connsys-id-probe/) | connsys id probe | 7 |
| [connsys-bootstrap](../research/connsys-bootstrap/) | connsys bootstrap | 12 |
| [connsys-hif-probe](../research/connsys-hif-probe/) | connsys hif probe | 12 |
| [uboot-script-runner](../research/uboot-script-runner/) | uboot script runner | 10 |
| [openwrt-ram1](../research/openwrt-ram1/) | Первый OpenWrt userspace на рабочем Linux/DSA | 30 |
| [openwrt-ram2-mcu](../research/openwrt-ram2-mcu/) | MCU transport и системный restart | 37 |
| [openwrt-ram3-mcu](../research/openwrt-ram3-mcu/) | Проверки очистки и состояния DMA | 37 |
| [openwrt-ram4-patch](../research/openwrt-ram4-patch/) | Загрузка патча MCU | 38 |
| [openwrt-ram5-main](../research/openwrt-ram5-main/) | Попытка запуска основной firmware | 39 |
| [openwrt-ram6-fwdl](../research/openwrt-ram6-fwdl/) | Исправление firmware-download режима | 41 |
| [openwrt-ram7-query](../research/openwrt-ram7-query/) | Runtime MCU query | 42 |
| [openwrt-ram8-irq](../research/openwrt-ram8-irq/) | IRQ MCU/RX1 | 45 |
| [openwrt-ram9-nvm](../research/openwrt-ram9-nvm/) | Источник NVM и roundtrip | 48 |
| [openwrt-ram10-nvm-wait](../research/openwrt-ram10-nvm-wait/) | Тайминги NVM | 44 |
| [openwrt-ram11-nvm-pad](../research/openwrt-ram11-nvm-pad/) | Padding NVM | 44 |
| [openwrt-ram12-devinfo](../research/openwrt-ram12-devinfo/) | DEVINFO | 45 |
| [openwrt-ram13-devinfo-var](../research/openwrt-ram13-devinfo-var/) | DEVINFO ABI | 45 |
| [openwrt-ram14-bss](../research/openwrt-ram14-bss/) | BSS-контекст | 46 |
| [openwrt-ram15-radio](../research/openwrt-ram15-radio/) | Радио/channel6 | 46 |
| [openwrt-ram16-beacon](../research/openwrt-ram16-beacon/) | Beacon offload, SSID ещё не виден | 47 |
| [openwrt-ram17-watch](../research/openwrt-ram17-watch/) | Контроль состояния HIF | 47 |
| [openwrt-ram18-rx](../research/openwrt-ram18-rx/) | Возврат RX0 | 50 |
| [openwrt-ram19-txd](../research/openwrt-ram19-txd/) | Формат TXD | 51 |
| [openwrt-ram20-state](../research/openwrt-ram20-state/) | Снимки состояния MAC/TSF | 54 |
| [openwrt-ram21-period](../research/openwrt-ram21-period/) | BSS period/DTIM: SSID появился на телефоне и ПК | 55 |
| [openwrt-ram22-client-rx](../research/openwrt-ram22-client-rx/) | RX management клиента | 57 |
| [openwrt-ram23-auth-tx](../research/openwrt-ram23-auth-tx/) | Передача auth-ответа | 61 |
| [openwrt-ram24-tx-free](../research/openwrt-ram24-tx-free/) | Возврат TX-free токенов | 65 |
| [openwrt-ram25-assoc](../research/openwrt-ram25-assoc/) | STA/ассоциация | 69 |
| [openwrt-ram26-echo](../research/openwrt-ram26-echo/) | Первый ARP/ICMP endpoint | 73 |
| [openwrt-ram27-window](../research/openwrt-ram27-window/) | Увеличенное окно; физический Wi-Fi ping подтверждён после исправления маршрута Windows | 75 |
| [openwrt-ram28-netdev](../research/openwrt-ram28-netdev/) | Linux netdev, DHCP и TCP/22; автоматическая аренда подтверждена | 87 |
| [openwrt-ram29-recycle](../research/openwrt-ram29-recycle/) | Reuse payload/token; аппаратная остановка на descriptor127 | 95 |
| [openwrt-ram30-ring128](../research/openwrt-ram30-ring128/) | Кольцо128; та же аппаратная остановка | 95 |
| [openwrt-ram31-scheduler](../research/openwrt-ram31-scheduler/) | OEM DMA scheduler; длительный обмен/обороты колец и токенов подтверждены | 98 |
| [uboot-autoboot-v1](../research/uboot-autoboot-v1/) | Сохранённая проба RAM-wrapper; затем заменена native U-Boot | 13 |
| [uboot-native-netboot-v1](../research/uboot-native-netboot-v1/) | Реальная модификация нормального U-Boot; AutoTFTP и LAN1 SSH подтверждены | 19 |
| [ssh-identity-v1](../research/ssh-identity-v1/) | Шаблон индивидуальной постоянной SSH-конфигурации; работа подтверждена владельцем | 14 |
| [cloud-host-setup](../research/cloud-host-setup/) | Исходные скрипты и версии пакетов подготовки облачной среды | 5 |
| [wifi-bringup](../research/wifi-bringup/) | Статический анализ формата трёхрегионной Wi-Fi firmware | 1 |
| [openwrt-ram32-cfg80211](../research/openwrt-ram32-cfg80211/) | cfg80211/nl80211 + штатный hostapd; AP/клиент/IP/TCP22/чистая остановка подтверждены на плате | 72 |
| [openwrt-ram33-reconnect](../research/openwrt-ram33-reconnect/) | повторное подключение при работающей AP: 8 подключений/8 отключений и чистая остановка подтверждены на плате | 78 |
| [openwrt-ram34-wpa2](../research/openwrt-ram34-wpa2/) | WPA2-PSK/CCMP через hostapd; программные проверки прошли, аппаратный тест ожидается | 89 |
| [openwrt-ram35-netup](../research/openwrt-ram35-netup/) | AP сохраняется после DHCP, SSID не найден, остановка чистая | 92 |
| [openwrt-ram36-beacon-diag](../research/openwrt-ram36-beacon-diag/) | SSID появился один раз, после reboot исчез; четыре снимка и чистые остановки получены | 95 |
| [openwrt-ram37-channel1](../research/openwrt-ram37-channel1/) | канал1/2412MHz подтверждён; SSID отсутствует, raw beacon0 через246,9секунды; stop чистый | 100 |

| [openwrt-ram38-bmc-profile](../research/openwrt-ram38-bmc-profile/) | SSID виден,2ассоциации; GMK/GTKsetupfailed; stop чистый | 105 |

| [openwrt-ram39-gtk-init](../research/openwrt-ram39-gtk-init/) | первый физический WPA2 handshake; reconnect не прошёл; helper guard исправлен отдельно | 108 |
| [ram40-wpa2-load-test](../research/ram40-wpa2-load-test/) | Сценарий длительного WPA2-теста Windows; MTU1400 подтверждён, разбор текущих задержек | 3 |

## Подтверждённый рубеж RAM31

Одно открытое подключение клиента:5126 парных завершений TX,5110 reuse payload,40 оборотов кольца, полный оборот4080 data token IDs. Ошибок ownership/stale/duplicate/early-token не зафиксировано. Штатная остановка: result/cleanup/critical=0; DMA idle и MCU stopped подтверждены; память остаётся закреплена до reboot.

Windows через Wi-Fi192.168.2.2:5000 отправлено/4999 получено/1 потеря (0,02%), затем94/94 keepalive, общая длительность241,3с, TCP22 доступен, DHCP подтверждён. Причина единственной потери не установлена. Это не тест предельной скорости или многоклиентной работы.

## Управление AP в RAM32

RAM32 подготовлена: стандартный cfg80211/nl80211 контроль и штатный hostapd для открытой AP, с сохранением транспорта RAM31 и персональных SSH-настроек. Пройдены2591 базовый+652 новых ASan/UBSan сценария,30+33 QEMU-команды настоящего cfg80211/hostapd и4 SSH-входа с закреплённой идентичностью. Радио/MCU/DMA в QEMU не эмулируются. Аппаратная проверка RAM32 пройдена21 октября2026 по времени Москвы: hostapd AP-ENABLED/AP-STA-CONNECTED,iw authorized/authenticated/associated,20/20 обычных и3/3 DF1372 ping,TCP22. Остановка AP/DMA/MCU прошла сresult/cleanup/critical=0;44/44 paireddataTX,inflight0,faults0. Подробности: [VALIDATION.md](../research/openwrt-ram32-cfg80211/VALIDATION.md). WPA2,повторная ассоциация и несколько клиентов ещё не реализованы. Двойной service delete/Not found отмечен как исправление помощника для следующей версии.

## Подтверждённый этап RAM33

После первого успешного подключения RAM32 клиент не смог подключиться снова
до stop. Однократный AUTH/ASSOC заменён циклом удаления/создания STA с ожиданием
TX DDONE и TX-free. Повторные команды MCU теперь могут циркулировать в кольце;
таймаут не разрешает переиспользовать занятую память. Новый session snapshot
показывает цикл без остановки AP. Пройдены214 новых native-сценариев,8 ARM-трасс
REASSOC и44+47 QEMU-команд настоящих cfg80211/hostapd с синтетическим peer;
базовые2591+18+652 проверки сохранены. Аппаратный тест RAM33 пройден 21 октября
2026 года по времени Москвы: 8 подключений (7 повторных) и 8 отключений при
одном AP start, STA create/delete=8/8, 43/43 подтверждённые команды MCU,
46/46 парных runtime TX и 10/10 показанных Windows ping. После последнего
отключения клиента stop завершился с result/cleanup/critical=0, DMA idle и
MCU stopped. [Подробности](../research/openwrt-ram33-reconnect/VALIDATION.md).
Кадров REASSOC в этом тесте не было; проверен DEAUTH → AUTH/ASSOC.
Один клиент/открытый канал6; WPA2 и AP stop/start без reboot не реализованы.

Следующий этап — WPA2 и дальнейшая интеграция со штатным управлением Wi-Fi.

## Подготовленный этап RAM34

Добавлены GTK/PTK, контролируемый EAPOL/IP-порт и CCMP PN при сохранении
переподключений RAM33. Штатный hostapd в QEMU прошёл настоящее WPA2-рукопожатие
с независимым синтетическим клиентом, отказ неправильного MIC и повторное
подключение. Пройдены3576 native,13 OEM ARM,31 QEMU и13 Linux-протокольных
проверок. Подтверждение установки ключа в QEMU синтетическое; физические
CCMP/MCU/RF и подключение клиента RAM34 ещё не проверены.

## RAM34: обнаруженная остановка AP; исправление RAM35

Владелец не увидел SSID RAM34. AP-ENABLED сменился пустой конфигурацией phy0
и AP-DISABLED через секунду: post-AP ifup в helper выполняет network reload и
down/up. Статус finished/result0, один start/stop,0 клиентов/EAPOL, GTK install
и32 ACK MCU-команд подтверждены. Это не подтверждает CCMP или соединение.

RAM35 настраивает netdev/netifd до AP без ifup/network reload, после DHCP
проверяет active/finished.36 новых QEMU WPA2/lifecycle проверок и13 проверок
инъекции пустой конфигурации прошли. Реальный аппаратный тайминг ifup QEMU
не воспроизвёл; эта граница проверки указана явно. Драйверные исходники и
полный Linux-патч прежние;3576 native и13 ARM cases унаследованы по хешам,
не перезапускались. Новый аппаратный тест RAM35 ожидается.

## RAM35: AP активна, SSID отсутствует; диагностика RAM36

RAM35 на плате сохранила AP после DHCP, приняла GTK/BMC и все команды,
но SSID не обнаружен. TSF шёл469 секунд, RX0 принимал соседние маяки,
клиентов не было. Чистый stop восстановил scheduler, остановил MCU/DMA.
Ноль старого beacon_end снят после GTK/BMC delete и не изолирует причину.
Попытка читать legacy report live ждала удерживаемый run-mutex; второй SSH
и stop подтвердили восстановление. Это ошибка предложенной диагностики.

RAM36 хранит четыре MAC-снимка до/после BMC/GTK и до очистки; новая diag
читает CPU-копию,13 legacy callbacks возвращают EBUSY при активном run.
3624 native,13 OEM ARM,32 ARM report callbacks,37 QEMU WPA2 integration и13
startup-removal cases прошли. Команды радио/ключей/маяка прежние; это диагностика,
не заявленное исправление RF. На плате владелец увидел C80-RAM36, но клиент
не подключал. Live/stopped diag вернули3/4снимка. До очистки при GTK/BMC live
счётчик357 через36,54секунды после установки ключа; причина отличия RAM35/36
не установлена. Остановка чистая,32commandsACK,0fault,MCU stopped/DMA idle.
Следующий тест — один WPA2/DHCP клиент на той же RAM36 после обычного reboot.

## RAM36: непостоянная видимость; RAM37 на канале1

После первого появления C80-RAM36 повторный reboot дал невидимую сеть.
Raw beacon low16=0 во всех четырёх снимках, в том числе через241,50секунды
после GTK. Управляющие MAC-регистры совпадают, AP активна, stop чистый,
клиентов нет. Причина непостоянства и помехи канала6 не установлены.

По запросу владельца RAM37 настраивает1/2412MHz в hostapd/cfg80211/MCU,
сохраняя WPA2 и диагностику.3700 native,19 OEM ARM,40 QEMU WPA2 и13
startup-removal checks прошли. Физическое радио в QEMU не эмулируется;
аппаратный результат RAM37 приведён ниже.

## RAM37: канал1 не помог; RAM38 повторяет нормальный BMC профиль

Владелец подтвердил6.12.113-c80-openwrt-ram37-channel1 и2412MHz, но SSID
не появился. Во всех четырёх снимках raw beacon low16=0; последний через
246,90секунды после GTK, активное окно246,915секунды. GTK/BMC live,
32ACK/9reuse/0fault, остановка чистая, клиентов нет. Помехи канала6 как
объяснение не подтверждены. Предыдущие исходники и архивы неизменяемы.

При ARM исполнении OEM normal-AP request обнаружена маска BMC0x2101.
Порт использовал сокращённую0x2001; настоящий builder добавляет tag8/len8/
flags1 между BASIC и WTBL, увеличивая тело244→252байта. RAM38 исправляет
это отличие, сохраняя канал1, BMC/GTK порядок, ключевые команды и668112Bpool.
Связь отличия с отсутствием маяков ещё не подтверждена на физическом радио.
3712 native,23 OEM ARM,40 QEMU WPA2 и13 startup-removal checks прошли.
Следующий аппаратный тест — C80-RAM38 через прежние TFTP/SSH.

## RAM38: SSID и ассоциация; RAM39: первый GTK refresh

В RAM38 сеть появилась, клиент дважды ассоциировался, начальные EAPOL2/2,
но hostapd GMK/GTK setup failed, driver refused2, PTK/authorization0.
Raw beacon1129 через115,58секунды после GTK, APactive115,595секунды,
36ACK/0fault, DMAidle/MCUstopped и штатное удержание clientTXpool до reboot.
Это один успешный поиск сети; причинность и повторяемость не установлены.

Обычный hostapd при первом клиенте заменяет GTK. Настоящий RAM38 core
воспроизводит отказ смены уже установленного ключа. RAM39 разрешает GTK
refresh до PTK/авторизации через два подтверждённых удаления и новую установку.
Одинаковый ключ не переустанавливается, активный PTK не заменяется. QEMU
использует общую политику вместо прежнего accept-all stub.3753 native,
23OEMARM,43QEMU/13startup-removal checks прошли. Физический тест ожидается.

## RAM39: физический WPA2 и ошибка helper

**Аппаратный результат RAM39:** после исправления ошибочного имени ядра в helper первый WPA2 handshake завершился: GTK refresh1, PTK/authorized1, EAPOL2/2, encryptedTX/RX7/29. После отключения клиента повторное подключение не прошло. Auth/assoc остались1/1, deauth/disassoc0, bad34→206; причины RXD-отбрасывания ещё не измерены. Остановка чистая: DMAidle/MCUstopped,72/72TX,41/41/41command, inflight0,MemAvailable7744KiB. Подтверждения DHCP-аренды, маршрута, ping и TCP ещё нет. Ошибка helper исправлена отдельно в [helper guard fix1](../research/ram39-helper-guard-fix/); исходный архив RAM39 не переписан.

| [ram39-helper-guard-fix](../research/ram39-helper-guard-fix/) | точное имя ядра в helper; внешний CPIO;15QEMU checks; kernel unchanged | 6 |

## RAM40: current-peer plaintext management RX gate

[RAM40](../research/openwrt-ram40-rx-status/) сохраняет первый GTK refresh, channel1 и ключевую политику RAM39. При живом PTK допускает обычные lifecycle management кадры того же peer с CCMP WCID/CipherMis, сохраняя проверки ошибок/RSN/данных. В report добавлены RX gate причины.3871native/48QEMU/13startup-removal checks пройдены. Исходные RXD-флаги неудачи RAM39 не сохранены. На RAM40 уже подтверждены три физических WPA2-handshake и два повторных подключения одного клиента; приняты три deauth с CCMP/CipherMis. Остановка чистая. Позднее подтверждены40/40ping без потерь иTCP22 дважды через физический Wi-Fi. Экспортировано108исходныхфайлов.

### Аппаратный результат RAM40

**Аппаратная проверка RAM40 пройдена для WPA2-переподключения:** один клиент
трижды завершил WPA2 handshake при одном запуске AP — два повторных подключения.
Драйвер принял три нешифрованных deauth с признаком CCMP/CipherMis;
первый RXD2=e0044001, FC=00c0. Прежний фильтр отверг бы именно такой кадр.
Ошибок ключей/PN/DMA нет: EAPOL6/6, encryptedTX/RX10/49,53/53/53команды,
20/20завершённых runtimeTX. Остановка чистая, DMAidle/MCUstopped,
inflight0, MemAvailable7760KiB. Пользователь сообщил, что ping не выполнял;
DHCP-аренда, маршрут и TCP отдельно ещё не подтверждены.

### RAM40: IP через WPA2

Последующая проверка IP на той же RAM40 также прошла: обе таблицы маршрутов
выбрали физический Wi-Fi с адреса192.168.2.2, ping20/20 +20/20 без потерь,
среднее10мс в обеих сериях, диапазоны4–19 и4–22мс. TCP/22 доступен дважды
через тот же Wi-Fi. Это подтверждает IP и доступность TCP-службы; сама
авторизация SSH этими командами не проверялась. Отключение клиента между
этими двумя сериями не указано; два WPA2-переподключения подтверждены
предыдущим отдельным отчётом. Следующий тест — крупные пакеты и длительная
нагрузка по WPA2 на той же сборке.

### RAM40: MTU и длительная нагрузка WPA2

Следующая проверка крупных пакетов также прошла: 10/10 DF ping с нагрузкой
1372 байта без потерь, MTU 1400, RTT 19–38 мс, среднее 24 мс.
Скорость передачи AP пока фиксирована на CCK1 (1 Мбит/с), обработчик
опрашивает DMA с usleep_range(1000,1050), а точные таймеры выключены
при HZ=100. Это объясняет вероятные источники задержки; вклад каждого
этапа аппаратно не измерен. Следующий тест — длительная нагрузка WPA2
на той же работающей AP: [сценарий Windows](../research/ram40-wpa2-load-test/).
Образы ядра и драйвер не изменены.

Новый сценарий проверяет5000малых и256крупных запросов, связь не менее240с
иTCP22; сохраняет частичный JSON при обрыве/смене маршрута.16проверок
управления/парсера пройдены вPowerShell7.5.4 с синтетическими эффектами.
Windows5.1 и физический прогон нового сценария ещё не проверены.
