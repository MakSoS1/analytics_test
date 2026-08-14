param(
    [string]$OutputDir = "$env:RUNNER_TEMP\remote-admin-v2-windows"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$etl = Join-Path $OutputDir "capture.etl"
$pcapng = Join-Path $OutputDir "capture.pcapng"
$formatted = Join-Path $OutputDir "capture.txt"
$fidelityPath = Join-Path $OutputDir "windows_fidelity.json"
$runnerPath = Join-Path $OutputDir "runner.json"
$sessionsPath = Join-Path $OutputDir "sessions.jsonl"
$tempSharePath = Join-Path $OutputDir "share"
$tempShareName = "AdminLabV2"

$protocols = @("openssh", "smb", "winrm", "dcom", "rdp")
$ports = @{
    openssh = @(22)
    smb = @(445)
    winrm = @(5985, 5986)
    dcom = @(135)
    rdp = @(3389)
}

$results = [ordered]@{}
foreach ($name in $protocols) {
    $results[$name] = [ordered]@{
        protocol = $name
        tool_present = $false
        service_present = $false
        wire_observed = $false
        session_completed = $false
        source_stack = "windows_native"
        target_stack = "windows_native"
        fidelity_status = "attempted_unverified"
        failure_reason = ""
    }
}

$runner = [ordered]@{
    os = [System.Environment]::OSVersion.VersionString
    computer_name = $env:COMPUTERNAME
    runner_os = $env:RUNNER_OS
    runner_arch = $env:RUNNER_ARCH
    image_os = $env:ImageOS
    image_version = $env:ImageVersion
    workflow_run_id = $env:GITHUB_RUN_ID
    workflow_sha = $env:GITHUB_SHA
    captured_at_utc = [DateTime]::UtcNow.ToString("o")
}
$runner | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 $runnerPath

function Write-SessionRecord {
    param(
        [string]$Protocol,
        [bool]$Completed,
        [string]$Detail
    )
    $record = [ordered]@{
        environment_id = "windows_native"
        protocol = $Protocol
        session_completed = $Completed
        detail = $Detail
        timestamp_utc = [DateTime]::UtcNow.ToString("o")
    }
    ($record | ConvertTo-Json -Compress -Depth 5) | Add-Content -Encoding UTF8 $sessionsPath
}

function Set-ProbeFailure {
    param([string]$Protocol, [System.Management.Automation.ErrorRecord]$Failure)
    $results[$Protocol].failure_reason = $Failure.Exception.Message
    Write-SessionRecord -Protocol $Protocol -Completed $false -Detail $Failure.Exception.Message
}

function Test-CapturedPort {
    param([string]$Text, [int[]]$CandidatePorts)
    foreach ($port in $CandidatePorts) {
        $patterns = @(
            "(?i)(DstPort|Destination Port|dport|dest port)[^0-9]{0,12}$port\b",
            "(?i)(SrcPort|Source Port|sport|source port)[^0-9]{0,12}$port\b",
            "(?i):$port\b"
        )
        foreach ($pattern in $patterns) {
            if ($Text -match $pattern) { return $true }
        }
    }
    return $false
}

# Start a single full-host packet capture before any probe. pktmon is a native
# Windows capture source; the resulting ETL and converted PCAPNG are retained.
try { & pktmon stop 2>$null | Out-Null } catch {}
try { & pktmon reset 2>$null | Out-Null } catch {}
& pktmon start --capture --pkt-size 0 --file-name $etl | Out-Null

$sshdWasPresent = $false
$sshdWasRunning = $false
$shareCreated = $false
$winrmWasRunning = $false
$authorizedKey = $null
$keyBase = Join-Path $OutputDir "v2_ssh_key"

try {
    # OpenSSH: use the Windows OpenSSH client and, when possible, the genuine
    # Windows OpenSSH server capability. Key material is ephemeral to this job.
    try {
        $ssh = Get-Command ssh.exe -ErrorAction SilentlyContinue
        $sshKeygen = Get-Command ssh-keygen.exe -ErrorAction SilentlyContinue
        $results.openssh.tool_present = [bool]($ssh -and $sshKeygen)
        $service = Get-Service sshd -ErrorAction SilentlyContinue
        if ($service) {
            $sshdWasPresent = $true
            $sshdWasRunning = $service.Status -eq "Running"
        } else {
            $capability = Get-WindowsCapability -Online | Where-Object Name -like "OpenSSH.Server*" | Select-Object -First 1
            if ($capability -and $capability.State -ne "Installed") {
                Add-WindowsCapability -Online -Name $capability.Name | Out-Null
            }
            $service = Get-Service sshd -ErrorAction SilentlyContinue
        }
        $results.openssh.service_present = [bool]$service
        if ($results.openssh.tool_present -and $service) {
            if ($service.Status -ne "Running") { Start-Service sshd }
            & ssh-keygen.exe -q -t ed25519 -N "" -f $keyBase | Out-Null
            $pub = Get-Content "$keyBase.pub" -Raw
            $authorizedKey = "C:\ProgramData\ssh\administrators_authorized_keys"
            New-Item -ItemType Directory -Force -Path (Split-Path $authorizedKey) | Out-Null
            Add-Content -Encoding ascii -Path $authorizedKey -Value $pub
            & icacls.exe $authorizedKey /inheritance:r /grant "Administrators:F" /grant "SYSTEM:F" | Out-Null
            $user = $env:USERNAME
            $output = & ssh.exe -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL -i $keyBase "$user@127.0.0.1" "whoami" 2>&1
            if ($LASTEXITCODE -eq 0 -and $output) {
                $results.openssh.session_completed = $true
                Write-SessionRecord -Protocol "openssh" -Completed $true -Detail ($output | Out-String).Trim()
            } else {
                throw "Windows OpenSSH bounded session did not complete: $($output | Out-String)"
            }
        }
    } catch { Set-ProbeFailure -Protocol "openssh" -Failure $_ }

    # SMB: create one explicit temporary Windows SMB share and exercise it with
    # the standard Windows UNC client path. No payload execution is performed.
    try {
        $results.smb.tool_present = [bool](Get-Command New-SmbShare -ErrorAction SilentlyContinue)
        $serverSvc = Get-Service LanmanServer -ErrorAction SilentlyContinue
        $results.smb.service_present = [bool]$serverSvc
        if ($results.smb.tool_present -and $serverSvc) {
            if ($serverSvc.Status -ne "Running") { Start-Service $serverSvc.Name }
            New-Item -ItemType Directory -Force -Path $tempSharePath | Out-Null
            Set-Content -Encoding UTF8 -Path (Join-Path $tempSharePath "server.txt") -Value "adminlab-v2"
            New-SmbShare -Name $tempShareName -Path $tempSharePath -FullAccess $env:USERNAME -ErrorAction Stop | Out-Null
            $shareCreated = $true
            $unc = "\\127.0.0.1\$tempShareName"
            $read = Get-Content (Join-Path $unc "server.txt") -Raw
            Set-Content -Encoding UTF8 -Path (Join-Path $unc "client.txt") -Value "bounded-client-write"
            if ($read -match "adminlab-v2" -and (Test-Path (Join-Path $tempSharePath "client.txt"))) {
                $results.smb.session_completed = $true
                Write-SessionRecord -Protocol "smb" -Completed $true -Detail "Windows SMB share read/write completed"
            } else {
                throw "Windows SMB bounded read/write validation failed"
            }
        }
    } catch { Set-ProbeFailure -Protocol "smb" -Failure $_ }

    # WinRM: enable the built-in Windows remoting stack and issue a bounded
    # remote command to localhost. Completion alone is insufficient: capture
    # evidence is still required before native_windows_validated is assigned.
    try {
        $results.winrm.tool_present = [bool](Get-Command Invoke-Command -ErrorAction SilentlyContinue)
        $winrm = Get-Service WinRM -ErrorAction SilentlyContinue
        $results.winrm.service_present = [bool]$winrm
        if ($winrm) { $winrmWasRunning = $winrm.Status -eq "Running" }
        if ($results.winrm.tool_present -and $winrm) {
            Enable-PSRemoting -SkipNetworkProfileCheck -Force | Out-Null
            $remoteName = Invoke-Command -ComputerName localhost -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop
            if ($remoteName) {
                $results.winrm.session_completed = $true
                Write-SessionRecord -Protocol "winrm" -Completed $true -Detail "PowerShell Remoting localhost command completed"
            }
        }
    } catch { Set-ProbeFailure -Protocol "winrm" -Failure $_ }

    # DCOM/WMI: force a CIM session using the DCOM protocol rather than WSMan.
    try {
        $results.dcom.tool_present = [bool](Get-Command New-CimSession -ErrorAction SilentlyContinue)
        $rpc = Get-Service RpcSs -ErrorAction SilentlyContinue
        $results.dcom.service_present = [bool]$rpc
        if ($results.dcom.tool_present -and $rpc) {
            $option = New-CimSessionOption -Protocol Dcom
            $cim = New-CimSession -ComputerName localhost -SessionOption $option -ErrorAction Stop
            try {
                $os = Get-CimInstance -CimSession $cim -ClassName Win32_OperatingSystem -ErrorAction Stop
                if ($os.Caption) {
                    $results.dcom.session_completed = $true
                    Write-SessionRecord -Protocol "dcom" -Completed $true -Detail "Native Windows CIM/DCOM query completed"
                }
            } finally {
                Remove-CimSession -CimSession $cim -ErrorAction SilentlyContinue
            }
        }
    } catch { Set-ProbeFailure -Protocol "dcom" -Failure $_ }

    # RDP: a GitHub-hosted runner generally cannot create a second interactive
    # self-session. Probe the genuine TermService/mstsc stack, but never call it
    # validated unless a bounded session and wire evidence both exist.
    try {
        $mstsc = Get-Command mstsc.exe -ErrorAction SilentlyContinue
        $term = Get-Service TermService -ErrorAction SilentlyContinue
        $results.rdp.tool_present = [bool]$mstsc
        $results.rdp.service_present = [bool]$term
        if ($term -and $term.Status -ne "Running") {
            try { Start-Service TermService -ErrorAction Stop } catch {}
        }
        $listener = Test-NetConnection -ComputerName 127.0.0.1 -Port 3389 -WarningAction SilentlyContinue
        if ($listener.TcpTestSucceeded) {
            Write-SessionRecord -Protocol "rdp" -Completed $false -Detail "Native TermService listener observed; interactive hosted-runner session not proven"
            $results.rdp.failure_reason = "interactive RDP session not proven on hosted runner"
        } else {
            $results.rdp.failure_reason = "TermService listener unavailable on hosted runner"
        }
    } catch { Set-ProbeFailure -Protocol "rdp" -Failure $_ }
}
finally {
    try { & pktmon stop | Out-Null } catch {}
    try { & pktmon pcapng $etl -o $pcapng | Out-Null } catch {}
    try { & pktmon format $etl -o $formatted | Out-Null } catch {}

    if ($shareCreated) {
        try { Remove-SmbShare -Name $tempShareName -Force -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    }
    if ($authorizedKey -and (Test-Path $authorizedKey)) {
        try {
            $content = Get-Content $authorizedKey -ErrorAction SilentlyContinue
            if (Test-Path "$keyBase.pub") {
                $pub = (Get-Content "$keyBase.pub" -Raw).Trim()
                @($content | Where-Object { $_.Trim() -ne $pub }) | Set-Content -Encoding ascii $authorizedKey
            }
        } catch {}
    }
    if ($sshdWasPresent -and -not $sshdWasRunning) {
        try { Stop-Service sshd -Force -ErrorAction SilentlyContinue } catch {}
    }
    if (-not $winrmWasRunning) {
        try { Stop-Service WinRM -Force -ErrorAction SilentlyContinue } catch {}
    }
}

$captureText = ""
if (Test-Path $formatted) {
    $captureText = Get-Content $formatted -Raw -ErrorAction SilentlyContinue
}
foreach ($name in $protocols) {
    $results[$name].wire_observed = Test-CapturedPort -Text $captureText -CandidatePorts $ports[$name]
    if ($results[$name].tool_present -and $results[$name].wire_observed -and $results[$name].session_completed) {
        $results[$name].fidelity_status = "native_windows_validated"
        $results[$name].failure_reason = ""
    } elseif ($name -eq "rdp" -and -not $results[$name].session_completed) {
        $results[$name].fidelity_status = "unavailable_hosted_runner"
    } else {
        $results[$name].fidelity_status = "attempted_unverified"
    }
}

$summary = [ordered]@{
    schema_version = 2
    environment_id = "windows_native"
    capture_source = "pktmon"
    capture_etl = $etl
    capture_pcapng = $pcapng
    protocols = $results
    validated_protocols = @($protocols | Where-Object { $results[$_].fidelity_status -eq "native_windows_validated" })
}
$summary | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 $fidelityPath
Write-Host ($summary | ConvertTo-Json -Depth 8)
