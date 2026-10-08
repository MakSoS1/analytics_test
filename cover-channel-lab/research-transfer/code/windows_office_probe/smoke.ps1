$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$root = Join-Path $env:RUNNER_TEMP "native-windows-office-probe"
New-Item -ItemType Directory -Path $root -Force | Out-Null
$etl = Join-Path $root "capture.etl"
$pcapng = Join-Path $root "capture.pcapng"
$report = Join-Path $root "report.json"
$checker = Join-Path $PSScriptRoot "audit.py"
$captureStarted = $false
try {
    if (-not (Get-Command pktmon -ErrorAction SilentlyContinue)) {
        throw "pktmon unavailable"
    }
    $targetIpFile = Join-Path $root "probe-target-ips.json"
    $probeIps = @(
        [System.Net.Dns]::GetHostAddresses("example.com") |
        ForEach-Object { $_.ToString() } |
        Select-Object -Unique
    )
    if ($probeIps.Count -lt 1 -or $probeIps.Count -gt 16) {
        throw "cannot establish bounded test-target IP allowlist"
    }
    [System.IO.File]::WriteAllText(
        $targetIpFile, (ConvertTo-Json -InputObject @($probeIps) -Compress)
    )
    & pktmon filter remove | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "pktmon filter reset failed" }
    $idx = 0
    foreach ($ip in $probeIps) {
        & pktmon filter add "ExampleTarget$idx" -i $ip -p 443 -t TCP | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "pktmon IP-scoped filter install failed" }
        $idx++
    }
    & pktmon start --capture --comp nics --pkt-size 0 --file-name $etl | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "pktmon start failed" }
    $captureStarted = $true

    # A short, public and credential-free probe. No office destinations, tokens,
    # cookies or user content. No PCAP leaves the runner.
    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.UseProxy = $false
    $client = [System.Net.Http.HttpClient]::new($handler)
    try {
        for ($i = 0; $i -lt 3; $i++) {
            $resp = $client.GetAsync("https://example.com/").GetAwaiter().GetResult()
            $resp.EnsureSuccessStatusCode() | Out-Null
            [void]$resp.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
            Start-Sleep -Milliseconds 5900
        }
    } finally {
        $client.Dispose()
        $handler.Dispose()
    }
    & pktmon stop | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "pktmon stop failed" }
    $captureStarted = $false
    & pktmon etl2pcap $etl --out $pcapng | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "pktmon conversion failed" }
    if (-not (Test-Path $pcapng)) { throw "pktmon pcapng was not created" }
    Write-Host "PKTMON_ETL_BYTES $((Get-Item $etl).Length)"
    Write-Host "PKTMON_PCAPNG_BYTES $((Get-Item $pcapng).Length)"
    & python $checker --pcapng $pcapng --report $report --port 443 --allowed-ips $targetIpFile
    if ($LASTEXITCODE -ne 0) { throw "native Windows HTTPS pcapng evidence insufficient" }
    $pcap = Join-Path $root "capture.pcap"
    $extractorReport = Join-Path $root "extractor-report.json"
    $extractorWork = Join-Path $root "extractor-work"
    & python (Join-Path $PSScriptRoot "extract_verified.py") --pcapng $pcapng --pcap $pcap --allowed-ips $targetIpFile --report $extractorReport --work $extractorWork
    if ($LASTEXITCODE -ne 0) { throw "native Windows production extraction failed" }
} finally {
    if ($captureStarted) { & pktmon stop | Out-Null }
    & pktmon filter remove | Out-Null
    Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $root "probe-target-ips.json")
    Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $root "capture.pcap")
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue (Join-Path $root "extractor-work")
    Remove-Item -Force -ErrorAction SilentlyContinue $etl
    Remove-Item -Force -ErrorAction SilentlyContinue $pcapng
}