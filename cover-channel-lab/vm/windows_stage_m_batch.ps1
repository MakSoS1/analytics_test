param(
  [Parameter(Mandatory=$true)][string]$Plan,
  [Parameter(Mandatory=$true)][string]$Agent,
  [Parameter(Mandatory=$true)][string]$OutDir,
  [int]$EventCap = 0
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
    IntervalSeconds = [double]$r.interval_seconds
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
  ($m | ConvertTo-Json -Compress) | Add-Content -Encoding utf8 $campaigns
  Get-Content $eventFile | Add-Content -Encoding utf8 $events
  Remove-Item $eventFile -Force -ErrorAction SilentlyContinue
  $count++
}
@{campaigns=$count;positive_only=$true;capture_environment="vm_wire";source_os="windows"} | ConvertTo-Json -Compress
