#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Shared by the router helper and real OpenWrt/QEMU lifecycle regression.
c80_wifi_network_prepare() {
    c80_prepare_state=$(cat "$1") || return 1
    case " $c80_prepare_state " in *' active=0 '*) ;; *) echo 'Network preparation must precede AP start.';return 1;; esac
    case " $c80_prepare_state " in *' finished=0 '*) ;; *) echo 'AP test has finished; reboot before preparing again.';return 1;; esac
    ubus -t 10 wait_for network.interface.wifi_ram || return 1
    # netifd treats wireless netdevs as external devices and leaves them
    # unavailable while IFF_UP is clear. Raise the netdev before START_AP;
    # this does not start a beacon or reload any network configuration.
    ifconfig c80wlan0 up || return 1
    ubus call network.interface.wifi_ram add_device '{"name":"c80wlan0"}' || return 1
    ubus call network.interface.wifi_ram up || return 1
    c80_net_wait=0
    while [ "$c80_net_wait" -lt 10 ]; do
        c80_net_state=$(ubus call network.interface.wifi_ram status) || return 1
        c80_net_up=$(printf '%s\n' "$c80_net_state" | jsonfilter -e '@.up')
        [ "$c80_net_up" = true ] && return 0
        sleep 1
        c80_net_wait=$((c80_net_wait+1))
    done
    echo 'Wi-Fi interface did not come up in netifd.'
    return 1
}
c80_wifi_assert_active() {
    c80_ap_state=$(cat "$1") || return 1
    case " $c80_ap_state " in *' active=1 '*) ;; *) echo 'AP is no longer active; collect c80-wifi report.';return 1;; esac
    case " $c80_ap_state " in *' finished=0 '*) return 0;; *) echo 'AP test has finished; collect c80-wifi report.';return 1;; esac
}
