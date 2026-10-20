#!/usr/bin/env bash
# Assemble verified upstream OpenWrt userspace; never build another board's image.
set -euo pipefail
c80_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ -r "$c80_root/../../activate.sh" ]]; then source "$c80_root/../../activate.sh"; fi
cd "$c80_root"
umask 077
c80_ib_name=openwrt-imagebuilder-25.12.5-mediatek-mt7629.Linux-x86_64
c80_ib_archive="$c80_ib_name.tar.zst"
mkdir -p downloads gnupg evidence
if [[ ! -f "downloads/$c80_ib_archive" ]]; then
    curl -fLSs --retry 2 --connect-timeout 15 --max-time 180 \
        "https://downloads.openwrt.org/releases/25.12.5/targets/mediatek/mt7629/$c80_ib_archive" \
        -o "downloads/$c80_ib_archive"
fi
GNUPGHOME="$c80_root/gnupg" gpg --batch --import downloads/openwrt-signing.asc > key-import.log 2>&1
GNUPGHOME="$c80_root/gnupg" gpg --batch --status-fd 1 \
    --verify downloads/sha256sums.asc downloads/sha256sums \
    > downloads/signature-status.txt 2> downloads/signature-verification.txt
python3 - <<'PY'
from pathlib import Path
import hashlib
p = Path('downloads')
primary = '8A8BC12F46B836C0F9CDB36F1D53D1877742E911'
assert any(line.startswith('[GNUPG:] VALIDSIG ') and line.endswith(primary)
           for line in (p / 'signature-status.txt').read_text().splitlines())
name = 'openwrt-imagebuilder-25.12.5-mediatek-mt7629.Linux-x86_64.tar.zst'
actual = hashlib.file_digest((p / name).open('rb'), 'sha256').hexdigest()
assert actual == '19e6cd97a6c20365057685b054b60e5040930467dc4bcdb136fcddd7e9314b32'
assert actual + ' *' + name in (p / 'sha256sums').read_text().splitlines()
PY
if [[ ! -d "$c80_ib_name" ]]; then tar --zstd -xf "downloads/$c80_ib_archive"; fi
if [[ -e rootfs ]]; then
    printf '%s\n' 'Existing rootfs kept. Use a fresh directory to rebuild userspace.' >&2
    exit 1
fi
mkdir rootfs
mapfile -t c80_packages < packages.lock
"$c80_ib_name/staging_dir/host/bin/apk" \
    --root "$c80_root/rootfs" --keys-dir "$c80_root/$c80_ib_name/keys" \
    --repositories-file "$c80_root/repositories" --cache-dir "$c80_root/apk-cache" \
    --no-network --no-logfile --no-scripts --arch arm_cortex-a7 \
    add --initdb --usermode "${c80_packages[@]}" > apk-install-usermode.log 2>&1
python3 prepare-rootfs.py
python3 verify-rootfs-abi.py
python3 make-initramfs-list.py
