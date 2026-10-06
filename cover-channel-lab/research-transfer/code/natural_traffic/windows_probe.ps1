$ErrorActionPreference = "Stop"
$pktmon = Get-Command pktmon -ErrorAction SilentlyContinue
$supported = $null -ne $pktmon
$reason = if ($supported) { "pktmon available" } else { "pktmon unavailable" }
[ordered]@{
  version = "natural-windows-capture-probe-v2"
  profile_id = "windows-native-http"
  capture_type = "pktmon"
  supported = $supported
  reason = $reason
  executable = if ($supported) { $pktmon.Source } else { $null }
  os = [System.Environment]::OSVersion.VersionString
} | ConvertTo-Json -Depth 4
