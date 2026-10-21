# RAM40 validation

**Аппаратная проверка RAM40 пройдена для WPA2-переподключения:** один клиент
трижды завершил WPA2 handshake при одном запуске AP — два повторных подключения.
Драйвер принял три нешифрованных deauth с признаком CCMP/CipherMis;
первый RXD2=e0044001, FC=00c0. Прежний фильтр отверг бы именно такой кадр.
Ошибок ключей/PN/DMA нет: EAPOL6/6, encryptedTX/RX10/49,53/53/53команды,
20/20завершённых runtimeTX. Остановка чистая, DMAidle/MCUstopped,
inflight0, MemAvailable7760KiB. В этом первом отчёте ping не выполнялся.

Последующая проверка IP на той же RAM40 также прошла: обе таблицы маршрутов
выбрали физический Wi-Fi с адреса192.168.2.2, ping20/20 +20/20 без потерь,
среднее10мс в обеих сериях, диапазоны4–19 и4–22мс. TCP/22 доступен дважды
через тот же Wi-Fi. Это подтверждает IP и доступность TCP-службы; сама
авторизация SSH этими командами не проверялась. Отключение клиента между
этими двумя сериями не указано; два WPA2-переподключения подтверждены
предыдущим отдельным отчётом.

Следующая проверка крупных пакетов также прошла: 10/10 DF ping с нагрузкой
1372 байта без потерь, MTU 1400, RTT 19–38 мс, среднее 24 мс.
Скорость передачи AP пока фиксирована на CCK1 (1 Мбит/с), обработчик
опрашивает DMA с usleep_range(1000,1050), а точные таймеры выключены
при HZ=100. Это объясняет вероятные источники задержки; вклад каждого
этапа аппаратно не измерен. Следующий тест — длительная нагрузка WPA2
на той же работающей AP: [сценарий Windows](../ram40-wpa2-load-test/).
Образы ядра и драйвер не изменены.



3871 fresh native ASan/UBSan cases (3753 retained,118 new RX gate), actual RX0/parser/session/key worker and synthetic descriptor/MCU effects. Original RAM39 gate reproduces refusal for synthetic current-peer plaintext auth with CCMP WCID/CipherMis. The original failed RAM39 frames were not captured. RAM40 now physically records an unprotected deauth with CCMP/CipherMis that the previous gate would reject, and three completed WPA2 handshakes in one AP run.

48 real stock hostapd/cfg80211/QEMU checks include five actual installed helper guard checks, two software WPA2 handshakes, wrong MIC, independent PMK/PTK/MIC/AES unwrap,13Linux network protocols, strict pinned SSH and32actualARMreportcallbacks.13more startup-removal checks pass. QEMU key/MCU/DMA/RF effects remain synthetic.

Full32-file patch and86729source entries restored without fuzz/offset. Rootfs601host/607CPIO/recovery3/45unchanged signed packages/66ELF, actual ARM decompressor6/handoff5/restart8 and RAM layout pass. DMApool668112B unchanged. Parent23OEMARM traces are inherited by byte-identical key/BMC/channel constructors, not rerun.

No firmware flash/UBoot update required. Physical WPA2 reconnect and clean shutdown are confirmed for one owner run. A later owner check confirms40/40pings andTCP22 twice via the physical Wi-Fi route. Interactive SSH authentication and DHCP lease table were not separately collected. Large DF packets later passed10/10; sustained encrypted load remains pending. Raw logs/private server keys/OEM blobs are never published. Source-manifest binds every exported original source to its frozen personal release.
