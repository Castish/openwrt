#!/usr/bin/env python3
"""Describe the supplied OEM MT7626 firmware; do not execute or redistribute it."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('firmware', type=Path)
parser.add_argument('--output', required=True, type=Path)
args = parser.parse_args()
data = args.firmware.read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert len(data) == 25808
assert digest == '76a9a4fb62be68725fba016d0814911255cf62b819d41760198dc7e3911322b5'
values = struct.unpack('<7B10s15sI', data[-36:])
chip, eco, count, version, flags, reserved1, reserved2, fwver, date, crc = values
assert (chip, eco, count, version, flags) == (9, 0, 3, 2, 1)
trailer_start = len(data) - 36 - count * 40
regions = []
body_used = 0
for index in range(count):
    trailer = data[trailer_start + index * 40:trailer_start + (index + 1) * 40]
    address, length = struct.unpack_from('<2I', trailer, 16)
    regions.append({'index': index, 'destination_address_in_mcu_image': hex(address),
                    'length': length, 'feature_set': trailer[24],
                    'first_four_le32_fields': list(struct.unpack_from('<4I', trailer))})
    body_used += length
separator = data[body_used:trailer_start]
assert separator == b'################\0\0\0\0################'
result = {
    'file': 'WIFI_RAM_CODE_7626.bin', 'bytes': len(data), 'sha256': digest,
    'analysis': 'Static format description only; no firmware was loaded into hardware.',
    'common_trailer_bytes': 36, 'region_trailer_bytes': 40,
    'chip_id_field': chip, 'eco_code_field': eco, 'regions_count': count,
    'format_version': version, 'format_flags': flags,
    'reserved_fields': [reserved1, reserved2],
    'firmware_version_ascii': fwver.rstrip(b'\0').decode('ascii'),
    'build_date_ascii': date.rstrip(b'\0').decode('ascii'),
    'trailer_crc_field': hex(crc), 'trailer_crc_validated': False,
    'regions': regions, 'total_region_payload_bytes': body_used,
    'separator_bytes': len(separator), 'separator_hex': separator.hex(),
    'length_accounting_valid': body_used + len(separator) + count * 40 + 36 == len(data),
    'layout_family': 'Linux mt7663_fw_buf / mt76_connac2_fw_trailer',
    'mt7663_driver_compatibility_established': False,
    'mcu_addresses_are_not_verified_cpu_physical_addresses': True,
}
args.output.write_text(json.dumps(result, indent=2) + '\n')
print('OEM firmware metadata: 3 regions, length accounting passed; host compatibility unverified.')
