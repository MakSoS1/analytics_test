$ErrorActionPreference = "Stop"
$pktmon = Get-Command pktmon -ErrorAction SilentlyContinue
$supported = $false
$reason = "Windows native capture backend not implemented; pktmon alone is insufficient"
[ordered]@{
  version = "natural-windows-capture-probe-v2"
  profile_id = "windows-native-http"
  capture_type = "pktmon"
  supported = $supported
  pktmon_available = ($null -ne $pktmon)
  reason = $reason
  executable = if ($supported) { $pktmon.Source } else { $null }
  os = [System.Environment]::OSVersion.VersionString
} | ConvertTo-Json -Depth 4