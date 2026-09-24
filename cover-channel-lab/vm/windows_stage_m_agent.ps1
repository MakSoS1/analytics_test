param(
  [Parameter(Mandatory=$true)][ValidateSet(
    "M-HTTPS-BEACON","M-HTTPS-FRONT","M-HTTPS-LOWENT","M-HTTPS-FRAG",
    "M-CLOUD-API","M-RMM-SHAPE","M-WSS-LONG","M-TUNNEL","M-DNS-BEACON","M-DNS-BULK"
  )][string]$Family,
  [Parameter(Mandatory=$true)][ValidateSet(
    "dotnet_httpclient_schannel","winhttp","curl_schannel","edge_chromium",
    "dotnet_clientwebsocket","windows_dns"
  )][string]$Stack,
  [Parameter(Mandatory=$true)][string]$CampaignId,
  [int]$Seed = 1,
  [int]$Events = 5,
  [double]$IntervalSeconds = 30,
  [double]$JitterFraction = 0.1,
  [string]$ServerHost = "cover-api.test",
  [string]$ServerIp = "10.20.0.20",
  [string]$Output = ".\events.jsonl"
)

$ErrorActionPreference = "Stop"
if ($Events -lt 1 -or $Events -gt 120) { throw "Events must be 1..120" }
if ($IntervalSeconds -lt 0 -or $IntervalSeconds -gt 7200) { throw "IntervalSeconds out of range" }
if ($JitterFraction -lt 0 -or $JitterFraction -gt 0.5) { throw "JitterFraction out of range" }
if ($ServerIp -notmatch '^10\.') { throw "VM corpus server must use a private lab address" }

$rng = [System.Random]::new($Seed)
$utf8 = [System.Text.Encoding]::UTF8
$script:Rows = [System.Collections.Generic.List[object]]::new()
$campaignStarted = [DateTimeOffset]::UtcNow.ToString("o")

function Add-Row([int]$I, [string]$Kind, [int]$Bytes, [string]$Extra="") {
  $script:Rows.Add([ordered]@{
    campaign_id = $CampaignId
    event_id = ('e{0:d3}' -f $I)
    event_type = $Kind
    sent_at = [DateTimeOffset]::UtcNow.ToString("o")
    encoded_length = $Bytes
    client_impl = $Stack
    scenario_id = $Family
    label_binary = 1
    extra = $Extra
  })
}

function Sleep-Jitter([int]$I) {
  if ($I -ge ($Events - 1)) { return }
  $factor = 1.0 + (($rng.NextDouble() * 2.0 - 1.0) * $JitterFraction)
  Start-Sleep -Milliseconds ([int]([Math]::Max(0, $IntervalSeconds * 1000.0 * $factor)))
}

function New-Payload([int]$I) {
  if ($Family -eq "M-HTTPS-LOWENT") {
    return $utf8.GetBytes(@("id=do","status=ok","cmd=1",([Guid]::NewGuid().ToString()))[$I % 4])
  }
  if ($Family -eq "M-HTTPS-FRAG") {
    return $utf8.GetBytes(([Guid]::NewGuid().ToString("N")).Substring(0, 2 + ($I % 5)))
  }
  $b = New-Object byte[] (32 + (($I % 4) * 24))
  $rng.NextBytes($b)
  return $b
}

function Invoke-DotNetHttp([string]$Url, [string]$Method, [byte[]]$Body) {
  $handler = [System.Net.Http.HttpClientHandler]::new()
  $handler.ServerCertificateCustomValidationCallback = { param($m,$c,$ch,$e) $true }
  $client = [System.Net.Http.HttpClient]::new($handler)
  try {
    $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::new($Method), $Url)
    if ($null -ne $Body -and $Body.Length -gt 0) {
      $req.Content = [System.Net.Http.ByteArrayContent]::new($Body)
      $req.Content.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::new("application/octet-stream")
    }
    $resp = $client.SendAsync($req).GetAwaiter().GetResult()
    return [int]$resp.StatusCode
  } finally { $client.Dispose(); $handler.Dispose() }
}

function Invoke-WinHttp([string]$Url, [string]$Method, [byte[]]$Body) {
  $w = New-Object -ComObject WinHttp.WinHttpRequest.5.1
  $w.Option(4) = 13056
  $w.Open($Method, $Url, $false)
  if ($null -ne $Body -and $Body.Length -gt 0) {
    $w.SetRequestHeader("Content-Type","application/octet-stream")
    $w.Send($Body)
  } else { $w.Send() }
  return [int]$w.Status
}

function Invoke-Curl([string]$Url, [string]$Method, [byte[]]$Body) {
  $tmp = [System.IO.Path]::GetTempFileName()
  try {
    if ($null -ne $Body) { [System.IO.File]::WriteAllBytes($tmp,$Body) }
    $args = @("-k","-sS","-o","NUL","-w","%{http_code}","-X",$Method)
    if ($null -ne $Body -and $Body.Length -gt 0) { $args += @("--data-binary","@$tmp") }
    $code = & curl.exe @args $Url
    if ($LASTEXITCODE -ne 0) { throw "curl.exe failed rc=$LASTEXITCODE" }
    return [int]$code
  } finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
}

function Get-EdgePath {
  $candidates = @(
    "$env:ProgramFiles(x86)\Microsoft\Edge\Application\msedge.exe",
    "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe"
  )
  foreach($p in $candidates) { if(Test-Path $p) { return $p } }
  $cmd = Get-Command msedge.exe -ErrorAction SilentlyContinue
  if($cmd) { return $cmd.Source }
  throw "Microsoft Edge is required for edge_chromium VM holdout"
}

function Invoke-EdgeHttp([string]$HostName, [string]$TargetPath, [string]$Method, [byte[]]$Body) {
  $edge = Get-EdgePath
  $b64 = if($null -eq $Body) { "" } else { [Convert]::ToBase64String($Body) }
  $fixture = "https://" + $HostName + ":8443/stage-m/http-fixture?target=" +
    [Uri]::EscapeDataString($TargetPath) + "&method=" + [Uri]::EscapeDataString($Method) +
    "&body=" + [Uri]::EscapeDataString($b64)
  $args = @(
    "--headless=new","--disable-gpu","--ignore-certificate-errors",
    "--disable-background-networking","--disable-component-update","--disable-sync",
    "--no-first-run","--virtual-time-budget=5000","--dump-dom",$fixture
  )
  & $edge @args | Out-Null
  if($LASTEXITCODE -ne 0) { throw "Edge HTTP fixture failed rc=$LASTEXITCODE" }
  return 200
}

function Invoke-EdgeWebSocketScenario {
  $edge = Get-EdgePath
  $mode = if($Family -eq "M-TUNNEL"){"tunnel"}else{"wss"}
  $fixture = "https://edge-front.test:8443/stage-m/ws-fixture?host=" +
    [Uri]::EscapeDataString($ServerHost) + "&events=" + $Events +
    "&seed=" + $Seed + "&mode=" + $mode
  $args = @(
    "--headless=new","--disable-gpu","--ignore-certificate-errors",
    "--disable-background-networking","--disable-component-update","--disable-sync",
    "--no-first-run","--virtual-time-budget=8000","--dump-dom",$fixture
  )
  & $edge @args | Out-Null
  if($LASTEXITCODE -ne 0) { throw "Edge WSS fixture failed rc=$LASTEXITCODE" }
  for($i=0; $i -lt $Events; $i++) {
    Add-Row $i "stage_m_windows_edge_wss" 0 "browser_native=1"
  }
}

function Invoke-HttpScenario([int]$I) {
  $payload = New-Payload $I
  $path = "/stage-m/beacon"
  $method = "POST"
  if ($Family -eq "M-HTTPS-FRAG") {
    $method = "GET"; $path = "/stage-m/item?id=" + [Convert]::ToHexString($payload).ToLower()
    $payload = $null
  } elseif ($Family -eq "M-CLOUD-API") {
    $id = [Guid]::NewGuid().ToString("N")
    $paths = @(
      "/v1.0/me/drive/items/$id/content",
      "/v4/spreadsheets/$id/values/A1",
      "/storage/v1/b/lab/o/$id",
      "/yandex/disk/resources?path=/lab/$id"
    )
    $path = $paths[$I % $paths.Count]
    $method = @("GET","GET","PUT","GET")[$I % 4]
    if ($method -eq "GET") { $payload = $null }
  } elseif ($Family -eq "M-RMM-SHAPE" -and $I -lt [Math]::Max(2,[int]($Events/2))) {
    $method = "GET"; $path = "/stage-m/poll?cursor=$I"; $payload = $null
  }
  $url = "https://" + $ServerHost + ":8443" + $path
  $status = switch ($Stack) {
    "dotnet_httpclient_schannel" { Invoke-DotNetHttp $url $method $payload }
    "winhttp" { Invoke-WinHttp $url $method $payload }
    "curl_schannel" { Invoke-Curl $url $method $payload }
    "edge_chromium" { Invoke-EdgeHttp $ServerHost $path $method $payload }
    default { Invoke-DotNetHttp $url $method $payload }
  }
  Add-Row $I "stage_m_windows_http" $(if($null -eq $payload){0}else{$payload.Length}) "status=$status"
}

function Invoke-WebSocketScenario {
  $uri = [Uri]("wss://" + $ServerHost + ":8443/ws")
  $ws = [System.Net.WebSockets.ClientWebSocket]::new()
  $ws.Options.RemoteCertificateValidationCallback = { param($s,$c,$ch,$e) $true }
  try {
    $ws.ConnectAsync($uri,[Threading.CancellationToken]::None).GetAwaiter().GetResult()
    for ($i=0; $i -lt $Events; $i++) {
      $payload = [Convert]::ToBase64String((New-Payload $i))
      $obj = if ($Family -eq "M-TUNNEL") {
        @{type="socks_data";conn_id=("w"+($i%4));data=$payload}
      } else {
        @{action=$(if($i%2){"send"}else{"recv"});container=$payload;target="LAB";message="STATUS"}
      }
      $txt = ($obj | ConvertTo-Json -Compress)
      $bytes = $utf8.GetBytes($txt)
      $seg = [ArraySegment[byte]]::new($bytes)
      $ws.SendAsync($seg,[System.Net.WebSockets.WebSocketMessageType]::Text,$true,[Threading.CancellationToken]::None).GetAwaiter().GetResult()
      $buf = New-Object byte[] 4096
      $recv = $ws.ReceiveAsync([ArraySegment[byte]]::new($buf),[Threading.CancellationToken]::None).GetAwaiter().GetResult()
      Add-Row $i "stage_m_windows_wss" $bytes.Length ("reply="+$recv.Count)
      Sleep-Jitter $i
    }
  } finally {
    if ($ws.State -eq [System.Net.WebSockets.WebSocketState]::Open) {
      $ws.CloseAsync([System.Net.WebSockets.WebSocketCloseStatus]::NormalClosure,"done",[Threading.CancellationToken]::None).GetAwaiter().GetResult()
    }
    $ws.Dispose()
  }
}

function Invoke-DnsScenario {
  for ($i=0; $i -lt $Events; $i++) {
    $raw = New-Payload $i
    $label = ([Convert]::ToHexString($raw).ToLower()).Substring(0,[Math]::Min(50,$raw.Length*2))
    $qtype = @("A","AAAA","TXT")[$i % 3]
    $name = "$label.stage-m.test"
    $null = Resolve-DnsName -Name $name -Type $qtype -Server $ServerIp -DnsOnly -ErrorAction Stop
    Add-Row $i "stage_m_windows_dns" $label.Length "qtype=$qtype"
    Sleep-Jitter $i
  }
}

if ($Stack -eq "windows_dns") {
  Invoke-DnsScenario
} elseif ($Stack -eq "dotnet_clientwebsocket") {
  Invoke-WebSocketScenario
} elseif ($Stack -eq "edge_chromium" -and $Family -in @("M-WSS-LONG","M-TUNNEL")) {
  Invoke-EdgeWebSocketScenario
} else {
  for ($i=0; $i -lt $Events; $i++) {
    Invoke-HttpScenario $i
    Sleep-Jitter $i
  }
}

$Rows | ForEach-Object { ($_ | ConvertTo-Json -Compress) } | Set-Content -Encoding utf8 $Output
$manifest = [ordered]@{
  campaign_id=$CampaignId; scenario_id=$Family; label_binary=1; label_family="cover_channel";
  label_intent="c2_or_tunnel_shape"; experiment_stage="M_positive_diversity";
  dataset_role="positive_corpus"; positive_only=$true; negative_class_present=$false;
  training_eligible=$true; capture_environment="vm_wire"; environment_tier="vm_wire";
  client_impl=$Stack; source_os="windows"; implementation_id=("windows-"+$Stack);
  requested_interval_seconds=$IntervalSeconds; jitter_fraction=$JitterFraction; expected_events=$Rows.Count;
  started_at=$campaignStarted; ended_at=[DateTimeOffset]::UtcNow.ToString("o");
  external_dependency=$false; post_exploitation=$false; arbitrary_forwarding=$false;
  status="success"; ground_truth_source="vm_native_agent"; generator_name="coverlab_windows_native_agent";
  generator_version="1.0.0"; capture_file="capture.pcapng"
}
$manifest | ConvertTo-Json -Compress
