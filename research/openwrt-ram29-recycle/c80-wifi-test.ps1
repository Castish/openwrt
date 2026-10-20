# Read-only Windows test of the connected C80 RAM Wi-Fi interface.
# Paste into PowerShell if local policy does not permit running script files.
$ErrorActionPreference = 'Stop'
$target = '192.168.2.1'
$route = Find-NetRoute -RemoteIPAddress $target
$route | Format-List IPAddress,InterfaceAlias,DestinationPrefix,NextHop
$source = ($route | Where-Object { $_.IPAddress } | Select-Object -First 1).IPAddress
if ($source -ne '192.168.2.2') {
    throw 'Wrong source/route. Connect physical Wi-Fi to C80-RAM16 and disable VPN/TUN.'
}
$ping = New-Object System.Net.NetworkInformation.Ping
$clock = [System.Diagnostics.Stopwatch]::StartNew()
$sent = 0
$received = 0
$consecutiveLost = 0
$lastStatus = 'NotStarted'
try {
    while ($sent -lt 5000 -and $clock.Elapsed.TotalSeconds -lt 300) {
        $sent++
        try { $lastStatus = $ping.Send($target, 1000).Status.ToString() }
        catch { $lastStatus = 'PingException' }
        if ($lastStatus -eq 'Success') { $received++; $consecutiveLost = 0 }
        else { $consecutiveLost++ }
        if ($consecutiveLost -ge 10) { break }
    }
    [pscustomobject]@{
        Test = 'TX descriptor/buffer/token reuse'; Source = $source
        Sent = $sent; Received = $received; Lost = $sent - $received
        Seconds = [math]::Round($clock.Elapsed.TotalSeconds, 1)
        LastStatus = $lastStatus
    } | Format-List
    if ($sent -ne 5000 -or $consecutiveLost -ge 10) {
        throw 'Burst stopped early. Keep this output and collect c80-wifi report after stop.'
    }
    $keepSent = 0
    $keepReceived = 0
    while ($clock.Elapsed.TotalSeconds -lt 240) {
        $keepSent++
        try { $lastStatus = $ping.Send($target, 1000).Status.ToString() }
        catch { $lastStatus = 'PingException' }
        if ($lastStatus -eq 'Success') { $keepReceived++; $consecutiveLost = 0 }
        else { $consecutiveLost++ }
        if ($consecutiveLost -ge 10) { break }
        Start-Sleep -Seconds 2
    }
    [pscustomobject]@{
        Test = 'Connection beyond the old 180-second window'
        Sent = $keepSent; Received = $keepReceived; Lost = $keepSent - $keepReceived
        TotalSeconds = [math]::Round($clock.Elapsed.TotalSeconds, 1)
        LastStatus = $lastStatus
    } | Format-List
    Test-NetConnection $target -Port 22
} finally {
    $ping.Dispose()
    $clock.Stop()
}
Write-Output 'Finished on Windows. In OpenWrt run c80-wifi stop, then status and report.'
