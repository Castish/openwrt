#!/usr/bin/env bash
set -euo pipefail
net_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$net_root/../../activate.sh"
gcc -D_GNU_SOURCE -std=c11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer "$net_root/verify-netdev.c" -o "$net_root/verify-netdev"
ASAN_OPTIONS=detect_leaks=1 "$net_root/verify-netdev" "$net_root/rootfs/lib/firmware/c80" "$net_root/stock-command-oracle.bin" "$net_root/stock-synthetic-eeprom.bin" "$net_root/stock-auth-txd.bin" "$net_root/stock-station-command-oracle.bin" "$net_root/stock-association-txd.bin" "$net_root/stock-data-txd.bin" "$net_root/data-protocol-fixtures.bin" > "$net_root/verification-netdev.log"
tail -2 "$net_root/verification-netdev.log"
