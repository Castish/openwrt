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

## Подтверждённый рубеж RAM31

Одно открытое подключение клиента:5126 парных завершений TX,5110 reuse payload,40 оборотов кольца, полный оборот4080 data token IDs. Ошибок ownership/stale/duplicate/early-token не зафиксировано. Штатная остановка: result/cleanup/critical=0; DMA idle и MCU stopped подтверждены; память остаётся закреплена до reboot.

Windows через Wi-Fi192.168.2.2:5000 отправлено/4999 получено/1 потеря (0,02%), затем94/94 keepalive, общая длительность241,3с, TCP22 доступен, DHCP подтверждён. Причина единственной потери не установлена. Это не тест предельной скорости или многоклиентной работы.

## Текущий следующий этап

RAM32 подготовлена: стандартный cfg80211/nl80211 контроль и штатный hostapd для открытой AP, с сохранением транспорта RAM31 и персональных SSH-настроек. Пройдены2591 базовый+652 новых ASan/UBSan сценария,30+33 QEMU-команды настоящего cfg80211/hostapd и4 SSH-входа с закреплённой идентичностью. Радио/MCU/DMA в QEMU не эмулируются. Аппаратная проверка RAM32 пройдена21 октября2026 по времени Москвы: hostapd AP-ENABLED/AP-STA-CONNECTED,iw authorized/authenticated/associated,20/20 обычных и3/3 DF1372 ping,TCP22. Остановка AP/DMA/MCU прошла сresult/cleanup/critical=0;44/44 paireddataTX,inflight0,faults0. Подробности: [VALIDATION.md](../research/openwrt-ram32-cfg80211/VALIDATION.md). WPA2,повторная ассоциация и несколько клиентов ещё не реализованы. Двойной service delete/Not found отмечен как исправление помощника для следующей версии.
