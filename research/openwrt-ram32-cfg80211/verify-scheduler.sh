#!/usr/bin/env bash
set -euo pipefail
scheduler_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$scheduler_root/../../activate.sh"
cd "$scheduler_root"
gcc -D_GNU_SOURCE -std=c11 -O1 -g -Wall -Wextra -Werror -Wno-unused-function -fsanitize=address,undefined -fno-omit-frame-pointer verify-scheduler.c -o verify-scheduler
ASAN_OPTIONS=detect_leaks=1 ./verify-scheduler rootfs/lib/firmware/c80 stock-command-oracle.bin stock-synthetic-eeprom.bin stock-auth-txd.bin stock-station-command-oracle.bin stock-association-txd.bin stock-data-txd.bin data-protocol-fixtures.bin > verification-scheduler.log
tail -n 2 verification-scheduler.log
