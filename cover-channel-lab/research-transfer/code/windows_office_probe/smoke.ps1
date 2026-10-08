$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$root = Join-Path $env:RUNNER_TEMP "native-windows-office-probe"
New-Item -ItemType Directory -Path $root -Force | Out-Null
$etl = Join-Path $root "capture.etl"
$pcapng = Join-Path $root "capture.pcapng"
$report = Join-Path $root "report.json"
$fixture = Join-Path $PSScriptRoot "server.py"
$checker = Join-Path $PSScriptRoot "audit.py"
$server = $null
$captureStarted = $false
try {
    if (-not (Get-Command pktmon -ErrorAction SilentlyContinue)) {
        throw "pktmon unavailable on Windows runner"
    }
    $server = Start-Process python -ArgumentList @(
        $fixture, "--root", $root, "--port", "18443"
    ) -PassThru -WindowStyle Hidden
    $open = $false
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        try {
            $tcp = [System.Net.Sockets.TcpClient]::new()
            $tcp.Connect("127.0.0.1", 18443)
            $tcp.Dispose()
            $open = $true
            break
        } catch { Start-Sleep -Milliseconds 200 }
    }
    if (-not $open) { throw "local fixture never became ready" }
    & pktmon filter remove | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "pktmon filter reset failed" }
    & pktmon filter add SyntheticTls -p 18443 -t TCP | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "pktmon filter install failed" }
    & pktmon start --capture --comp all --pkt-size 0 --file-name $etl | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "pktmon start failed" }
    $captureStarted = $true

    $handler = [System.Net.Http.HttpClientHandler]::new()
    # Use the .NET static delegate: a PowerShell scriptblock callback can fail
    # on a background TLS validation thread without an attached runspace.
    $handler.UseProxy = $false
    $handler.ServerCertificateCustomValidationCallback = [System.Net.Http.HttpClientHandler]::DangerousAcceptAnyServerCertificateValidator
    $client = [System.Net.Http.HttpClient]::new($handler)
    try {
        for ($i = 0; $i -lt 4; $i++) {
            $resp = $client.GetAsync("https://127.0.0.1:18443/health?i=$i").GetAwaiter().GetResult()
            $resp.EnsureSuccessStatusCode() | Out-Null
            [void]$resp.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
            Start-Sleep -Milliseconds 1800
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
    & python $checker --pcapng $pcapng --report $report
    if ($LASTEXITCODE -ne 0) { throw "pcapng evidence does not pass" }
} finally {
    if ($captureStarted) { & pktmon stop | Out-Null }
    & pktmon filter remove | Out-Null
    if ($null -ne $server -and -not $server.HasExited) { Stop-Process -Id $server.Id -Force }
    Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $root "fixture-key.pem")
    Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $root "fixture-cert.pem")
    Remove-Item -Force -ErrorAction SilentlyContinue $etl
    Remove-Item -Force -ErrorAction SilentlyContinue $pcapng
}