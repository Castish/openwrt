#Requires -Version 5.1
# SPDX-License-Identifier: MIT
# C80 RAM40: connected-client traffic test. No network settings are changed.
Set-StrictMode -Version 2.0

function Get-C80Path {
    $rows = @(Find-NetRoute -RemoteIPAddress '192.168.2.1' -ErrorAction Stop |
        Where-Object { $null -ne $_.PSObject.Properties['IPAddress'] })
    if ($rows.Count -ne 1) { throw 'Cannot identify one IPv4 source route.' }
    [pscustomobject]@{
        Source = [string]$rows[0].IPAddress
        InterfaceAlias = [string]$rows[0].InterfaceAlias
        InterfaceIndex = [int]$rows[0].InterfaceIndex
    }
}
function Assert-C80Path($Baseline) {
    $now = Get-C80Path
    if ($now.Source -ne '192.168.2.2') {
        throw 'Wrong source route. Connect Wi-Fi to C80-RAM40 with automatic IPv4.'
    }
    if ($null -ne $Baseline -and
        ($now.InterfaceIndex -ne $Baseline.InterfaceIndex -or $now.Source -ne $Baseline.Source)) {
        throw 'The network interface changed during the test.'
    }
    return $now
}
function New-C80Ping { New-Object System.Net.NetworkInformation.Ping }
function New-C80Clock { [System.Diagnostics.Stopwatch]::StartNew() }
function Get-C80Seconds($Clock) { return $Clock.Elapsed.TotalSeconds }
function Wait-C80Interval([int]$Milliseconds) { Start-Sleep -Milliseconds $Milliseconds }
function Get-C80Tcp {
    Test-NetConnection -ComputerName '192.168.2.1' -Port 22 -InformationLevel Detailed -WarningAction SilentlyContinue
}

function Invoke-C80Phase {
    param($Ping, $Clock, $Baseline, $Stats, [int]$Count,
          [double]$UntilSeconds, [double]$DeadlineSeconds)
    $begin = Get-C80Seconds $Clock
    [byte[]]$payload = New-Object byte[] $Stats.PayloadBytes
    for ($i = 0; $i -lt $payload.Length; $i++) { $payload[$i] = [byte]($i % 251) }
    $options = New-Object System.Net.NetworkInformation.PingOptions(64, $true)
    $consecutive = 0
    Write-Output ('Starting: ' + $Stats.Test) | Out-Host
    try {
        while (($Count -gt 0 -and $Stats.Sent -lt $Count) -or
               ($Count -eq 0 -and (Get-C80Seconds $Clock) -lt $UntilSeconds)) {
            if (((Get-C80Seconds $Clock) - $begin) -ge $DeadlineSeconds) {
                throw ('Phase deadline exceeded: ' + $Stats.Test)
            }
            if ($Stats.Sent % $(if ($Count -gt 0) { 500 } else { 5 }) -eq 0) {
                $null = Assert-C80Path $Baseline
            }
            $Stats.Sent++
            $reply = $null
            try {
                $reply = $Ping.Send('192.168.2.1', 1000, $payload, $options)
                $Stats.LastStatus = $reply.Status.ToString()
            } catch { $Stats.LastStatus = 'PingException' }
            if ($Stats.LastStatus -eq 'Success') {
                if ($reply.Address.ToString() -ne '192.168.2.1') {
                    $Stats.LastStatus = 'WrongReplyAddress'
                } elseif ($null -eq $reply.Buffer -or $reply.Buffer.Length -ne $payload.Length) {
                    $Stats.LastStatus = 'EchoPayloadMismatch'
                } else {
                    for ($i = 0; $i -lt $payload.Length; $i++) {
                        if ($reply.Buffer[$i] -ne $payload[$i]) {
                            $Stats.LastStatus = 'EchoPayloadMismatch'; break
                        }
                    }
                }
            }
            if ($Stats.LastStatus -eq 'Success') {
                $Stats.Received++; $consecutive = 0
                $rtt = [long]$reply.RoundtripTime; $Stats.RttTotalMs += $rtt
                if ($null -eq $Stats.MinMs -or $rtt -lt $Stats.MinMs) { $Stats.MinMs = $rtt }
                if ($null -eq $Stats.MaxMs -or $rtt -gt $Stats.MaxMs) { $Stats.MaxMs = $rtt }
            } else { $Stats.Lost++; $consecutive++ }
            if ($consecutive -ge 10) { throw ('Ten consecutive failed probes: ' + $Stats.LastStatus) }
            if ($Count -eq 0) { Wait-C80Interval 2000 }
        }
        $Stats.Completed = $true
    } finally {
        $Stats.Seconds = [math]::Round((Get-C80Seconds $Clock) - $begin, 3)
        if ($Stats.Received -gt 0) {
            $Stats.AverageMs = [math]::Round($Stats.RttTotalMs / $Stats.Received, 2)
        }
        $Stats | Select-Object Test,PayloadBytes,Sent,Received,Lost,Seconds,AverageMs,MinMs,MaxMs,LastStatus,Completed | Format-List | Out-Host
    }
}

function Invoke-C80WifiLoad {
    [CmdletBinding()]
    param([string]$OutputDirectory = $PSScriptRoot,
          [ValidateRange(1,100000)][int]$SmallCount = 5000,
          [ValidateRange(1,10000)][int]$LargeCount = 256,
          [ValidateRange(0,600)][int]$MinimumSeconds = 240)
    $ErrorActionPreference = 'Stop'
    $clock = New-C80Clock
    $ping = $null
    $report = [pscustomobject]@{
        Test = 'C80 RAM40 WPA2 connected-client load'
        StartedUtc = [datetime]::UtcNow.ToString('o')
        Target = '192.168.2.1'; Source = $null; InterfaceAlias = $null
        MinimumSeconds = $MinimumSeconds; TotalSeconds = 0
        Completed = $false; ZeroLoss = $false; Failure = $null
        Tcp22 = $false; TcpSource = $null; ResultFile = $null
        Phases = New-Object System.Collections.ArrayList
    }
    try {
        if (-not [System.IO.Directory]::Exists($OutputDirectory)) {
            throw 'The result directory must already exist.'
        }
        $baseline = Assert-C80Path $null
        $report.Source = $baseline.Source; $report.InterfaceAlias = $baseline.InterfaceAlias
        $baseline | Format-List | Out-Host
        Write-Output ('Keep Wi-Fi connected. This test runs for at least ' + $MinimumSeconds + ' seconds.') | Out-Host
        $ping = New-C80Ping
        foreach ($spec in @(
            @{ Name='Small packet descriptor/buffer/token reuse'; Size=32; Count=$SmallCount; Deadline=300 },
            @{ Name='MTU 1400 encrypted traffic, DF'; Size=1372; Count=$LargeCount; Deadline=120 },
            @{ Name='Connection remains usable beyond 180 seconds'; Size=32; Count=0; Deadline=300 }
        )) {
            $stats = [pscustomobject]@{
                Test=$spec.Name; PayloadBytes=$spec.Size; Sent=0; Received=0; Lost=0
                Seconds=0; RttTotalMs=[long]0; AverageMs=$null; MinMs=$null; MaxMs=$null
                LastStatus='NotStarted'; Completed=$false
            }
            [void]$report.Phases.Add($stats)
            Invoke-C80Phase -Ping $ping -Clock $clock -Baseline $baseline -Stats $stats `
                -Count $spec.Count -UntilSeconds $MinimumSeconds -DeadlineSeconds $spec.Deadline
        }
        $null = Assert-C80Path $baseline
        $tcp = Get-C80Tcp
        $report.Tcp22 = [bool]$tcp.TcpTestSucceeded
        $report.TcpSource = $tcp.SourceAddress.ToString()
        if (-not $report.Tcp22 -or $report.TcpSource -ne $baseline.Source) {
            throw 'TCP/22 did not succeed through the expected Wi-Fi source.'
        }
        $null = Assert-C80Path $baseline
        $report.Completed = $true
        $report.ZeroLoss = (@($report.Phases | Where-Object { $_.Lost -gt 0 }).Count -eq 0)
    } catch { $report.Failure = $_.Exception.Message }
    finally {
        if ($null -ne $ping) { $ping.Dispose() }
        $report.TotalSeconds = [math]::Round((Get-C80Seconds $clock), 3)
        $clock.Stop()
        if ([System.IO.Directory]::Exists($OutputDirectory)) {
            $leaf = 'c80-wifi-load-' + [datetime]::UtcNow.ToString('yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0,8) + '.json'
            $report.ResultFile = Join-Path $OutputDirectory $leaf
            $json = $report | ConvertTo-Json -Depth 6
            [System.IO.File]::WriteAllText($report.ResultFile, $json, (New-Object System.Text.UTF8Encoding($false)))
        }
        $report | Select-Object Completed,ZeroLoss,TotalSeconds,Tcp22,TcpSource,Failure,ResultFile | Format-List | Out-Host
    }
    if (-not $report.Completed) {
        throw ('Stopped. Save the result and collect c80-wifi report through LAN1. ' + $report.Failure)
    }
    Write-Output 'Finished. Through LAN1 run c80-wifi stop, wait for Finished in status, then collect c80-wifi report.'
}

if ($MyInvocation.InvocationName -ne '.') { Invoke-C80WifiLoad }
