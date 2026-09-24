param(
  [Parameter(Mandatory=$true)][string]$Plan,
  [Parameter(Mandatory=$true)][string]$Agent,
  [Parameter(Mandatory=$true)][string]$OutDir,
  [int]$EventCap = 0,
  [double]$TimeScale = 0.001,
  [double]$MaxSleepSeconds = 0.05
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$campaigns = Join-Path $OutDir "campaigns.jsonl"
$events = Join-Path $OutDir "events.jsonl"
Remove-Item $campaigns,$events -Force -ErrorAction SilentlyContinue

$rows = Get-Content $Plan | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json }
$count = 0
foreach ($r in $rows) {
  if ($r.client_os -ne "windows") { continue }
  $n = [int]$r.event_count
  if ($EventCap -gt 0) { $n = [Math]::Min($n,$EventCap) }
  $eventFile = Join-Path $OutDir ("events-" + $r.campaign_id + ".jsonl")
  $params = @{
    Family = [string]$r.family
    Stack = [string]$r.client_impl
    CampaignId = [string]$r.campaign_id
    Seed = 27000000 + ([int]$r.spec_index * 1009)
    Events = $n
    IntervalSeconds = [Math]::Min(([double]$r.interval_seconds * $TimeScale), $MaxSleepSeconds)
    JitterFraction = [double]$r.jitter_fraction
    Output = $eventFile
  }
  $manifest = & $Agent @params
  if ($LASTEXITCODE -ne 0) { throw "Windows agent failed for $($r.campaign_id)" }
  $m = $manifest | Select-Object -Last 1 | ConvertFrom-Json
  $m | Add-Member -NotePropertyName split_role -NotePropertyValue $r.split_role -Force
  $m | Add-Member -NotePropertyName implementation_id -NotePropertyValue $r.implementation_id -Force
  $m | Add-Member -NotePropertyName interval_bucket_seconds -NotePropertyValue $r.interval_bucket_seconds -Force
  $m | Add-Member -NotePropertyName event_count_bucket -NotePropertyValue $r.event_count_bucket -Force
  $m | Add-Member -NotePropertyName volume_mode -NotePropertyValue $r.volume_mode -Force
  $m | Add-Member -NotePropertyName direction_asymmetry -NotePropertyValue $r.asymmetry -Force
  $m | Add-Member -NotePropertyName payload_mode -NotePropertyValue $r.payload_mode -Force
  $m | Add-Member -NotePropertyName server_impl -NotePropertyValue $r.server_impl -Force
  $m | Add-Member -NotePropertyName source_ip -NotePropertyValue $r.source_ip -Force
  $m | Add-Member -NotePropertyName persona -NotePropertyValue $r.client_id -Force
  $m | Add-Member -NotePropertyName network_topology -NotePropertyValue $r.network_topology -Force
  $m | Add-Member -NotePropertyName network_profile_id -NotePropertyValue "vm_router" -Force
  $m | Add-Member -NotePropertyName requested_interval_seconds -NotePropertyValue ([double]$r.interval_seconds) -Force
  $m | Add-Member -NotePropertyName timing_scale -NotePropertyValue $TimeScale -Force
  $isTiming = $r.family -in @("M-HTTPS-BEACON","M-WSS-LONG","M-RMM-SHAPE","M-TIMING-XCARRIER")
  $timingReal = [Math]::Abs($TimeScale - 1.0) -lt 0.000001
  $eligible = [bool]$r.training_eligible -and ((-not $isTiming) -or $timingReal)
  $m | Add-Member -NotePropertyName training_eligible -NotePropertyValue $eligible -Force
  $m | Add-Member -NotePropertyName timing_training_eligible -NotePropertyValue $timingReal -Force
  $m | Add-Member -NotePropertyName timing_fidelity -NotePropertyValue $(if($timingReal){"wire_real"}else{"accelerated_shape_only"}) -Force
  $protocol = if($r.family -match "^M-DNS"){"dns"}elseif($r.family -in @("M-WSS-LONG","M-TUNNEL")){"wss"}else{"https"}
  $m | Add-Member -NotePropertyName protocol -NotePropertyValue $protocol -Force
  $m | Add-Member -NotePropertyName carrier -NotePropertyValue ($r.family.ToLower().Replace("m-","").Replace("-","_")) -Force
  $encrypted = $protocol -in @("https","wss")
  $m | Add-Member -NotePropertyName visibility_mode -NotePropertyValue $(if($encrypted){"opaque_and_ground_truth"}else{"content"}) -Force
  $m | Add-Member -NotePropertyName inspection_policy -NotePropertyValue $(if($encrypted){"bypass"}else{"not_applicable"}) -Force
  $m | Add-Member -NotePropertyName inspection_outcome -NotePropertyValue $(if($encrypted){"encrypted"}else{"plaintext"}) -Force
  $m | Add-Member -NotePropertyName sni_visibility -NotePropertyValue $(if($encrypted){"clear"}else{"not_applicable"}) -Force
  $m | Add-Member -NotePropertyName feature_availability_bitmap -NotePropertyValue "runtime" -Force
  ($m | ConvertTo-Json -Compress) | Add-Content -Encoding utf8 $campaigns
  Get-Content $eventFile | Add-Content -Encoding utf8 $events
  Remove-Item $eventFile -Force -ErrorAction SilentlyContinue
  $count++
}
@{campaigns=$count;positive_only=$true;capture_environment="vm_wire";source_os="windows"} | ConvertTo-Json -Compress
