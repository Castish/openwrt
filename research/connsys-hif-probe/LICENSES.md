# Components

Own bootstrap source, assembly/layout glue, script generator, verification
and package tools, and the unchanged C80 script-runner helper are MIT.
See LICENSE. The script-runner source was issued previously in
../uboot-script-runner/c80-script-runner.zip; its byte-identical helper
binary is included here for convenience.

blobs/test_mcu.bin and blobs/test_wifi.bin are unchanged binary components
from the user's supplied Archer C80(RU)_V1_240812.zip. Their original OEM
licensing is not replaced by the MIT notice on the surrounding helper.
FIRMWARE-SOURCES.json records exact origins, hashes and placement.
They are also embedded unchanged in the test payload. This artifact is
prepared for the user's own supplied router/firmware investigation and
is not a claim of a generally redistributable upstream firmware release.

No full proprietary TPOS executable, full factory U-Boot, flash dump,
individual calibration, MAC address or device password is included.
