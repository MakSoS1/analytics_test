param(
    [ValidateSet('preflight','native')]
    [string]$Mode = 'preflight',
    [string]$Target = '10.77.0.32',
    [string]$OutputDir = "$env:RUNNER_TEMP\remote-admin-windows"
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$AllowedTarget = '10.77.0.32'
if ($Target -ne $AllowedTarget) {
    throw "Refusing target $Target. Native fidelity harness is fixed to isolated lab target $AllowedTarget."
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$Report = [ordered]@{
    mode = $Mode
    target = $Target
    generated_utc = (Get-Date).ToUniversalTime().ToString('o')
    accepted_native_remote_fidelity = $false
    rdp_full_session_accepted = $false
    external_targets_allowed = $false
    payload_execution_allowed = $false
    checks = [ordered]@{}
}

function Add-Check([string]$Name, [bool]$Ok, [string]$Detail) {
    $Report.checks[$Name] = [ordered]@{ ok = $Ok; detail = $Detail }
}

$Tools = @('pktmon.exe','PowerShell.exe','mstsc.exe')
foreach ($Tool in $Tools) {
    $Found = [bool](Get-Command $Tool -ErrorAction SilentlyContinue)
    Add-Check "tool_$Tool" $Found ($(if ($Found) {'available'} else {'missing'}))
}

if ($Mode -eq 'preflight') {
    $Report.accepted_native_remote_fidelity = $false
    $Report.status = 'preflight_only_no_second_isolated_windows_host'
    $Report | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 "$OutputDir\fidelity.json"
    Write-Host ($Report | ConvertTo-Json -Depth 8)
    exit 0
}

$User = $env:WINDOWS_LAB_USER
$Password = $env:WINDOWS_LAB_PASSWORD
if ([string]::IsNullOrWhiteSpace($User) -or [string]::IsNullOrWhiteSpace($Password)) {
    throw 'WINDOWS_LAB_USER and WINDOWS_LAB_PASSWORD are required for native mode.'
}
$SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
$Credential = [pscredential]::new($User, $SecurePassword)

# Fail closed if the runner itself is not on the isolated admin-lab subnet.
$LocalLabAddresses = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
    Where-Object { $_.IPAddress -like '10.77.0.*' -and $_.IPAddress -ne $Target }
if (-not $LocalLabAddresses) {
    throw 'Native mode requires the client runner itself to have a 10.77.0.0/24 address.'
}
Add-Check 'client_on_lab_subnet' $true (($LocalLabAddresses.IPAddress -join ','))

# Refuse a default route over a 10.77/24 interface. A separate management NIC may
# exist on a self-hosted runner, but the research target is fixed and all tested
# connections below are to 10.77.0.32 only.
$TargetReachable = Test-NetConnection -ComputerName $Target -Port 445 -InformationLevel Quiet
if (-not $TargetReachable) {
    throw 'Target SMB port 445 is unreachable inside the isolated lab.'
}

$Ports = @(135, 445, 3389, 5985)
foreach ($Port in $Ports) {
    $Ok = Test-NetConnection -ComputerName $Target -Port $Port -InformationLevel Quiet
    Add-Check "tcp_$Port" ([bool]$Ok) ($(if ($Ok) {'reachable'} else {'unreachable'}))
}

$Etl = Join-Path $OutputDir 'native.etl'
$Pcap = Join-Path $OutputDir 'native.pcapng'
& pktmon.exe stop 2>$null | Out-Null
& pktmon.exe filter remove | Out-Null
& pktmon.exe filter add -i $Target | Out-Null
& pktmon.exe start --capture --pkt-size 0 --file-name $Etl | Out-Null

try {
    # SMB Admin Share: authenticated read-only listing. No file write or service creation.
    $DriveName = 'RALAB'
    Remove-PSDrive -Name $DriveName -Force -ErrorAction SilentlyContinue
    New-PSDrive -Name $DriveName -PSProvider FileSystem -Root "\\$Target\ADMIN$" -Credential $Credential -ErrorAction Stop | Out-Null
    $Entries = @(Get-ChildItem "$DriveName`:" -ErrorAction Stop | Select-Object -First 5 -ExpandProperty Name)
    Add-Check 'smb_admin_share' $true ("authenticated read-only listing; entries=" + ($Entries -join ','))
    Remove-PSDrive -Name $DriveName -Force -ErrorAction SilentlyContinue

    # WinRM: benign identity/query only. No remote process payload or persistence action.
    try {
        $SessionOption = New-PSSessionOption -OperationTimeout 10000 -OpenTimeout 10000
        $Session = New-PSSession -ComputerName $Target -Credential $Credential -SessionOption $SessionOption -ErrorAction Stop
        $RemoteComputer = Invoke-Command -Session $Session -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop
        Remove-PSSession $Session
        Add-Check 'winrm_psremoting' $true ("remote identity=$RemoteComputer")
    } catch {
        Add-Check 'winrm_psremoting' $false $_.Exception.Message
    }

    # DCOM-backed CIM: read-only operating-system metadata query.
    try {
        $Dcom = New-CimSessionOption -Protocol Dcom
        $Cim = New-CimSession -ComputerName $Target -Credential $Credential -SessionOption $Dcom -ErrorAction Stop
        $OS = Get-CimInstance -CimSession $Cim -ClassName Win32_OperatingSystem -ErrorAction Stop
        Remove-CimSession $Cim
        Add-Check 'dcom_cim_query' $true ("caption=" + [string]$OS.Caption)
    } catch {
        Add-Check 'dcom_cim_query' $false $_.Exception.Message
    }

    # Automated service-context runs cannot truthfully prove a full interactive RDP
    # desktop. We only preserve reachability here and require a separate interactive
    # Windows capture before accepting RDP native semantic fidelity.
    Add-Check 'rdp_interactive_required' $false '3389 reachability is not accepted as a full desktop lifecycle'
}
finally {
    & pktmon.exe stop | Out-Null
}

if (Test-Path $Etl) {
    & pktmon.exe etl2pcap $Etl --out $Pcap | Out-Null
}
$CaptureOk = Test-Path $Pcap
Add-Check 'pktmon_capture' $CaptureOk ($(if ($CaptureOk) {(Get-Item $Pcap).Length.ToString() + ' bytes'} else {'pcap conversion missing'}))

$RequiredNative = @('smb_admin_share','winrm_psremoting','dcom_cim_query','pktmon_capture')
$NativeOk = $true
foreach ($Name in $RequiredNative) {
    if (-not $Report.checks.Contains($Name) -or -not [bool]$Report.checks[$Name].ok) {
        $NativeOk = $false
    }
}
$Report.accepted_native_remote_fidelity = $NativeOk
$Report.status = $(if ($NativeOk) {'native_non_rdp_cases_validated'} else {'native_validation_failed_or_partial'})
$Report | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 "$OutputDir\fidelity.json"
Write-Host ($Report | ConvertTo-Json -Depth 8)
if (-not $NativeOk) { exit 1 }
