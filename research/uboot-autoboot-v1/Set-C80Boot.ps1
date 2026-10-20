param(
    [string]$Kernel = 'c80-openwrt-ram31-scheduler-zImage',
    [string]$Dtb = 'c80-openwrt-ram31-scheduler.dtb',
    [string]$Handoff = 'c80-openwrt-ram31-handoff.bin'
)
$ErrorActionPreference = 'Stop'
if (-not ('C80BootCrc32' -as [type])) {
    Add-Type -TypeDefinition @'
public static class C80BootCrc32 {
    public static uint Compute(byte[] data) {
        uint crc = 0xffffffff;
        foreach (byte value in data) {
            crc ^= value;
            for (int bit = 0; bit < 8; ++bit)
                crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
        }
        return ~crc;
    }
}
'@
}
$items = @(
    @{ Name = $Kernel; Address = '41000000'; Max = 0xc00000 },
    @{ Name = $Dtb; Address = '40f00000'; Max = 0x100000 },
    @{ Name = $Handoff; Address = '40e00000'; Max = 0x100000 }
)
$lines = @('C80SCRIPT1')
foreach ($item in $items) {
    if ($item.Name -notmatch '^[A-Za-z0-9_.-]{1,95}$' -or $item.Name -in @('.', '..')) {
        throw 'Use a simple file name in this folder, without a path.'
    }
    $path = Join-Path $PSScriptRoot $item.Name
    $bytes = [System.IO.File]::ReadAllBytes($path)
    if ($bytes.Length -eq 0 -or $bytes.Length -gt $item.Max) {
        throw ('Invalid image size: ' + $item.Name)
    }
    $size = '{0:x}' -f $bytes.Length
    $crc = '{0:x8}' -f [C80BootCrc32]::Compute($bytes)
    $lines += ('load {0} {1} {2} {3}' -f $item.Address, $item.Name, $size, $crc)
    $item.SizeHex = $size
    $item.CrcHex = $crc
}
$lines += 'go 40e00000'
$lines += 'end'
$text = ($lines -join "`n") + "`n"
if ($text.Length -gt 4096) { throw 'Manifest is too large.' }
$output = Join-Path $PSScriptRoot 'c80-start.txt'
$temporary = Join-Path $PSScriptRoot ('c80-start-' + [guid]::NewGuid().ToString('N') + '.tmp')
[System.IO.File]::WriteAllText($temporary, $text, [System.Text.Encoding]::ASCII)
if ([System.IO.File]::Exists($output)) {
    [System.IO.File]::Replace($temporary, $output, $null)
} else {
    [System.IO.File]::Move($temporary, $output)
}
Write-Output 'Updated c80-start.txt after checking all three images.'
Write-Output $text
