param(
    [Parameter(Mandatory=$true)][string]$OutputDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$etl = Join-Path $OutputDir "v3-extra.etl"
$pcapng = Join-Path $OutputDir "v3-extra.pcapng"
$formatted = Join-Path $OutputDir "v3-extra.txt"
$resultPath = Join-Path $OutputDir "v3-extra.json"

$result = [ordered]@{
    schema_version = 3
    dcom = [ordered]@{
        tool_present = [bool](Get-Command New-CimSession -ErrorAction SilentlyContinue)
        session_completed = $false
        target = ""
        detail = ""
    }
    rdp = [ordered]@{
        tool_present = [bool](Get-Command mstsc.exe -ErrorAction SilentlyContinue)
        listener_observed = $false
        mstsc_started = $false
        session_completed = $false
        detail = ""
    }
}

$term = Get-Service TermService -ErrorAction SilentlyContinue
$termWasRunning = $false
if ($term) { $termWasRunning = $term.Status -eq "Running" }
$rdpReg = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$oldDeny = $null
try { $oldDeny = (Get-ItemProperty -Path $rdpReg -Name fDenyTSConnections -ErrorAction Stop).fDenyTSConnections } catch {}

try {
    # Prepare local services before capture so the extra trace focuses on the
    # bounded DCOM/RDP network probes rather than setup operations.
    try {
        if ($term -and $term.Status -ne "Running") { Start-Service TermService -ErrorAction SilentlyContinue }
        Set-ItemProperty -Path $rdpReg -Name fDenyTSConnections -Value 0 -ErrorAction SilentlyContinue
    } catch {}

    try { & pktmon stop 2>$null | Out-Null } catch {}
    try { & pktmon reset 2>$null | Out-Null } catch {}
    & pktmon start --capture --pkt-size 0 --file-name $etl | Out-Null

    # Force DCOM down a network-addressed path. Hostname is preferred, followed
    # by the runner's non-loopback IPv4 address. A successful local CIM call that
    # never produces TCP/135 is intentionally insufficient for V3 validation.
    if ($result.dcom.tool_present) {
        $targets = New-Object System.Collections.Generic.List[string]
        if ($env:COMPUTERNAME) { $targets.Add($env:COMPUTERNAME) }
        try {
            Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
                Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.IPAddress -notlike '169.254.*' } |
                ForEach-Object { if (-not $targets.Contains($_.IPAddress)) { $targets.Add($_.IPAddress) } }
        } catch {}
        foreach ($target in $targets) {
            try {
                $option = New-CimSessionOption -Protocol Dcom
                $cim = New-CimSession -ComputerName $target -SessionOption $option -ErrorAction Stop
                try {
                    $os = Get-CimInstance -CimSession $cim -ClassName Win32_OperatingSystem -ErrorAction Stop
                    if ($os.Caption) {
                        $result.dcom.session_completed = $true
                        $result.dcom.target = $target
                        $result.dcom.detail = "Network-addressed native CIM/DCOM query completed"
                        break
                    }
                } finally {
                    Remove-CimSession -CimSession $cim -ErrorAction SilentlyContinue
                }
            } catch {
                $result.dcom.detail = "DCOM target $target failed: $($_.Exception.Message)"
            }
        }
    }

    # Native mstsc handshake attempt. The non-interactive hosted runner normally
    # cannot prove authentication/desktop creation, so session_completed stays
    # false unless a future evidence collector can prove that separately.
    if ($result.rdp.tool_present) {
        try {
            $listener = Test-NetConnection -ComputerName 127.0.0.1 -Port 3389 -WarningAction SilentlyContinue
            $result.rdp.listener_observed = [bool]$listener.TcpTestSucceeded
            if ($listener.TcpTestSucceeded) {
                $proc = Start-Process -FilePath mstsc.exe -ArgumentList '/v:127.0.0.1','/admin' -PassThru
                $result.rdp.mstsc_started = $true
                Start-Sleep -Seconds 8
                if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
                $result.rdp.detail = "Native mstsc launched against local TermService; authenticated interactive session not asserted"
            } else {
                $result.rdp.detail = "TermService TCP/3389 listener unavailable on hosted runner"
            }
        } catch {
            $result.rdp.detail = "Native mstsc bounded probe failed: $($_.Exception.Message)"
        }
    }
}
finally {
    try { & pktmon stop | Out-Null } catch {}
    try { & pktmon pcapng $etl -o $pcapng | Out-Null } catch {}
    try { & pktmon format $etl -o $formatted | Out-Null } catch {}
    if ($null -ne $oldDeny) {
        try { Set-ItemProperty -Path $rdpReg -Name fDenyTSConnections -Value $oldDeny -ErrorAction SilentlyContinue } catch {}
    }
    if ($term -and -not $termWasRunning) {
        try { Stop-Service TermService -Force -ErrorAction SilentlyContinue } catch {}
    }
}

$result | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 $resultPath
Write-Host ($result | ConvertTo-Json -Depth 8)
