# RAM39: GTK при первом клиенте

В RAM38 SSID был виден; клиент дважды ассоциировался и обменялся начальными
EAPOL, но драйвер refused2 и hostapd GMK/GTK setup failed. PTK/authorization0.
Аппаратный тест RAM39 ожидается. Повторяемость видимости пока не установлена.

Обычный hostapd обновляет GTK при первом клиенте, несмотря на rekey0. Старый
настоящий core RAM38 воспроизводит отказ; новый выполняет delete/delete/install
до PTK/авторизации. Обе команды удаления должны ACK+DDONE до установки.
Та же политика add/reinstall применяется к QEMU backend вместо accept-all.
Ключевые форматы, BMC252/tag8, канал1 и первоначальные beacon snapshots сохранены.

- 3753 свежих native ASan/UBSan cases:3712 прежних и41новый refresh case,
  включая27ошибок на3командах, no-inflight/идемпотентность/PN/refusal/live-PTK.
  Отдельно исполнен настоящий родительский RAM38 core и воспроизведён отказ.
- 23 свежих OEM ARM cases прежних key/BMC/radio пакетов; тела команд не менялись.
- 43 QEMU stock hostapd/cfg80211/OpenWrt checks. Настоящий hostapd выполнил
  first-station GTK refresh через общую политику; GMK/GTK setup failed нет.
  Независимые PMK/PTK/MIC/AESunwrap, неверный MIC, два подключения,
  13LinuxDHCP/IP/TCP cases, pinnedSSH и32actualARMreportcallbacks сохранены.
  Ещё13startup-removal checks проверяют остановку AP.
- Полный32-файловый patch/86729source entries восстановлены без fuzz/offset;
  rootfs601host/607CPIO/recovery3/45прежних signed packages/66ELF,
  decompressor6/handoff5/restart8/layout проверены. Pool668112B/offsets прежние.

Native device effects и QEMU MCU/DMA/key backend синтетические; физические
CCMP/RF не эмулируются. Программа на устройстве должна подтвердить первый
завершённый WPA2/DHCP/IP обмен. Один клиент,CCK/20MHz/MTU1400,GTK не передаёт
multicast, периодический rekey отключён; AP restart в одной загрузке не поддержан.
Персональные образы/ключи/OEM inputs и сырые аппаратные логи не публикуются.
