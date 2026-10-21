#Requires -Version 5.1
# SPDX-License-Identifier: MIT
# Execute actual test control flow with independent route/probe/time fixtures.
# These fixtures do not emulate a router, Windows WLAN, firmware or RF.
param([string]$ResultRoot = (Join-Path $PSScriptRoot 'private'))
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'c80-wifi-load.ps1')
[void][System.IO.Directory]::CreateDirectory($ResultRoot)
$RunRoot=Join-Path $ResultRoot ('run-'+[guid]::NewGuid().ToString('N'))
[void][System.IO.Directory]::CreateDirectory($RunRoot)
$script:Fixture = $null
function Out-Host { process { } }
function Find-NetRoute {
    [CmdletBinding()]
    param([string]$RemoteIPAddress)
    if ($RemoteIPAddress -ne '192.168.2.1') { throw 'Unexpected test target' }
    $script:Fixture.RouteCalls++
    if ($script:Fixture.Mode -eq 'missing-route') {
        return [pscustomobject]@{ InterfaceIndex=7; InterfaceAlias='fixture'; NextHop='0.0.0.0' }
    }
    $source='192.168.2.2'; $index=7
    if ($script:Fixture.Mode -eq 'wrong-source') { $source='198.18.0.1' }
    if ($script:Fixture.Mode -eq 'route-change' -and $script:Fixture.RouteCalls -ge 3) { $index=9 }
    [pscustomobject]@{ IPAddress=$source; InterfaceIndex=$index; InterfaceAlias='fixture-wifi' }
    [pscustomobject]@{ DestinationPrefix='192.168.2.0/24'; InterfaceIndex=$index; InterfaceAlias='fixture-wifi'; NextHop='0.0.0.0' }
}
function New-C80Clock {
    $c=[pscustomobject]@{ Seconds=[double]0; Stopped=$false }
    $c | Add-Member -MemberType ScriptMethod -Name Stop -Value { $this.Stopped=$true }
    $script:Fixture.Clock=$c
    return $c
}
function Get-C80Seconds($Clock) { return $Clock.Seconds }
function Wait-C80Interval([int]$Milliseconds) { $script:Fixture.Clock.Seconds += $Milliseconds/1000.0 }
function New-C80Ping {
    $script:Fixture.Created++
    $p=[pscustomobject]@{ Disposed=$false }
    $p | Add-Member -MemberType ScriptMethod -Name Dispose -Value {
        $this.Disposed=$true; $script:Fixture.Disposed++
    }
    $p | Add-Member -MemberType ScriptMethod -Name Send -Value {
        param($Target,$Timeout,$Payload,$Options)
        if ($Target -ne '192.168.2.1' -or $Timeout -ne 1000 -or
            -not $Options.DontFragment -or $Options.Ttl -ne 64 -or
            $Payload.Length -notin @(32,1372)) { throw 'Unexpected probe contract' }
        $f=$script:Fixture; $f.Probes++
        if ($Payload.Length -eq 1372) { $f.LargeProbes++ }
        $delay=0.01; if ($Payload.Length -eq 1372) { $delay=0.03 }
        if ($f.Mode -eq 'deadline') { $delay=0.1 }
        $status='Success'
        if ($f.Mode -eq 'ten-losses' -or
            ($f.Mode -eq 'isolated-loss' -and $f.Probes -eq 100) -or
            ($f.Mode -eq 'large-losses' -and $f.LargeProbes -gt 0) -or
            ($f.Mode -eq 'keep-losses' -and $f.Probes -gt 5256)) {
            $status='TimedOut'; $delay=1
        }
        $f.Clock.Seconds += $delay
        if ($f.Mode -eq 'exception') { throw 'Synthetic network exception' }
        [byte[]]$echo=$Payload.Clone()
        if ($f.Mode -eq 'wrong-payload') { $echo[0]=$echo[0] -bxor 1 }
        if ($f.Mode -eq 'short-payload') { $echo=[byte[]]@(1,2) }
        $address='192.168.2.1'; if ($f.Mode -eq 'wrong-address') { $address='192.168.2.9' }
        [pscustomobject]@{ Status=$status; Address=[System.Net.IPAddress]::Parse($address); Buffer=$echo; RoundtripTime=[long]($delay*1000) }
    }
    return $p
}
function Test-NetConnection {
    [CmdletBinding()]
    param([string]$ComputerName,[int]$Port,[string]$InformationLevel)
    if ($ComputerName -ne '192.168.2.1' -or $Port -ne 22 -or $InformationLevel -ne 'Detailed') { throw 'Unexpected TCP check' }
    $script:Fixture.TcpCalls++
    $ip='192.168.2.2'; if ($script:Fixture.Mode -eq 'tcp-wrong-source') { $ip='198.18.0.1' }
    [pscustomobject]@{ TcpTestSucceeded=($script:Fixture.Mode -ne 'tcp-refused'); SourceAddress=[System.Net.IPAddress]::Parse($ip) }
}
function Require([bool]$Condition,[string]$Message) {
    if (-not $Condition) { throw $Message }
}
$cases=New-Object System.Collections.ArrayList
foreach ($mode in @('success','wrong-source','missing-route','route-change','ten-losses',
    'wrong-payload','short-payload','wrong-address','exception','isolated-loss',
    'deadline','large-losses','keep-losses','tcp-refused','tcp-wrong-source')) {
    $script:Fixture=[pscustomobject]@{
        Mode=$mode; RouteCalls=0; Created=0; Disposed=0; Clock=$null; Probes=0; LargeProbes=0; TcpCalls=0
    }
    $dir=Join-Path $RunRoot $mode; [void][System.IO.Directory]::CreateDirectory($dir)
    $thrown=$false
    try { $null=Invoke-C80WifiLoad -OutputDirectory $dir } catch { $thrown=$true }
    $files=@(Get-ChildItem $dir -Filter '*.json')
    Require ($files.Count -eq 1) ($mode+': one complete or partial report must survive')
    $report=Get-Content $files[0].FullName -Raw | ConvertFrom-Json
    $okay=$mode -in @('success','isolated-loss')
    Require ($report.Completed -eq $okay -and $thrown -ne $okay) ($mode+': completion/failure contract')
    Require ($script:Fixture.Clock.Stopped) ($mode+': clock always stopped')
    Require ($script:Fixture.Created -eq $script:Fixture.Disposed) ($mode+': ping disposed on every path')
    if ($okay) {
        Require ($report.Phases[0].Sent -eq 5000 -and $report.Phases[1].Sent -eq 256) ($mode+': full small+MTU bursts')
        Require ($report.TotalSeconds -ge 240 -and $report.Phases[2].Sent -gt 0) ($mode+': beyond old 180-second window')
        Require ($report.Tcp22 -and $report.TcpSource -eq '192.168.2.2') ($mode+': TCP only from selected source')
        Require ($report.ZeroLoss -eq ($mode -eq 'success')) ($mode+': loss is not hidden')
    }
    switch ($mode) {
        'wrong-source' { Require ($script:Fixture.Created -eq 0) 'VPN route refused before first probe' }
        'missing-route' { Require ($script:Fixture.Created -eq 0) 'Missing source refused before first probe' }
        'route-change' { Require ($report.Phases[0].Sent -eq 500) 'Interface switch detected at next checkpoint' }
        'ten-losses' { Require ($report.Phases[0].Sent -eq 10) 'Ten consecutive losses stop burst' }
        'wrong-payload' { Require ($report.Phases[0].LastStatus -eq 'EchoPayloadMismatch') 'Full echo bytes checked' }
        'short-payload' { Require ($report.Phases[0].LastStatus -eq 'EchoPayloadMismatch') 'Echo length checked' }
        'wrong-address' { Require ($report.Phases[0].LastStatus -eq 'WrongReplyAddress') 'Reply address checked' }
        'exception' { Require ($report.Phases[0].LastStatus -eq 'PingException') 'Probe exceptions bounded' }
        'isolated-loss' { Require ($report.Phases[0].Lost -eq 1) 'Isolated loss counted without aborting entire run' }
        'deadline' { Require ($report.Phases[0].Sent -lt 5000 -and $report.Failure -like '*deadline*') 'Slow burst deadline' }
        'large-losses' { Require ($report.Phases.Count -eq 2 -and $report.Phases[1].Sent -eq 10) 'MTU failure retains small results' }
        'keep-losses' { Require ($report.Phases.Count -eq 3 -and $report.Phases[2].Sent -eq 10) 'Keepalive failure stops and retains bursts' }
        'tcp-refused' { Require ($script:Fixture.TcpCalls -eq 1 -and -not $report.Tcp22) 'TCP failure cannot report complete' }
        'tcp-wrong-source' { Require (-not $report.Completed) 'TCP source route must match' }
    }
    [void]$cases.Add($mode)
    Write-Output ('PASS LOAD CONTROL '+$mode)
}
# Real .NET overload, DF option and echo payload validation on local loopback.
$loopbackPassed=0; $loopbackUnavailable=$null
$ping=New-Object System.Net.NetworkInformation.Ping
try {
    foreach ($size in @(32,1372)) {
        [byte[]]$payload=New-Object byte[] $size
        for ($i=0;$i -lt $size;$i++) { $payload[$i]=[byte]($i%251) }
        try {
            $r=$ping.Send('127.0.0.1',1000,$payload,(New-Object System.Net.NetworkInformation.PingOptions(64,$true)))
        } catch {
            if ($env:OS -ne 'Windows_NT' -and $_.Exception.Message -like '*ping*utility could not be found*') {
                $loopbackUnavailable='Linux host has no system ping utility required by the .NET implementation.'
                Write-Output ('NOT EXERCISED: actual .NET loopback; '+$loopbackUnavailable)
                break
            }
            throw
        }
        Require ($r.Status.ToString() -eq 'Success' -and $r.Buffer.Length -eq $size) 'Actual .NET loopback send/DF overload'
        for ($i=0;$i -lt $size;$i++) { Require ($r.Buffer[$i] -eq $payload[$i]) 'Actual loopback echo contents' }
        [void]$cases.Add('real-dotnet-loopback-DF-'+$size)
        $loopbackPassed++
        Write-Output ('PASS LOAD CONTROL real-dotnet-loopback-DF-'+$size)
    }
} finally { $ping.Dispose() }
$tokens=$null;$errors=$null
$null=[System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'c80-wifi-load.ps1'),[ref]$tokens,[ref]$errors)
Require ($errors.Count -eq 0) 'Production script parses'
[void]$cases.Add('actual-PowerShell-parser')
$result=[pscustomobject]@{
    Passed=$true; CasesPassed=$cases.Count; Cases=@($cases)
    Runtime=$PSVersionTable.PSVersion.ToString(); WindowsPowerShell51Executed=$false
    ProductionScriptSha256=(Get-FileHash (Join-Path $PSScriptRoot 'c80-wifi-load.ps1') -Algorithm SHA256).Hash.ToLowerInvariant()
    VerifierSha256=(Get-FileHash $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
    ActualDotnetLoopbackCasesPassed=$loopbackPassed; ActualDotnetLoopbackUnavailable=$loopbackUnavailable
    PhysicalRouterOrRFEmulated=$false
}
$result | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $ResultRoot 'verification.json') -Encoding UTF8
Write-Output ('PASS: '+$cases.Count+' checks; route/time/probe fixtures are synthetic; real-loopback passes='+$loopbackPassed)
