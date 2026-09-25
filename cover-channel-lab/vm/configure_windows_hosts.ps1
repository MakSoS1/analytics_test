param(
  [string]$ServerMain = "10.20.0.20",
  [string]$ServerWss = "10.20.0.21",
  [string]$ServerFront = "10.20.0.22",
  [string]$Resolver = "10.20.0.23"
)
$ErrorActionPreference = "Stop"
$path = "$env:SystemRoot\System32\drivers\etc\hosts"
$begin = "# BEGIN COVERLAB STAGE M"
$end = "# END COVERLAB STAGE M"
$lines = Get-Content $path -ErrorAction Stop
$out = [System.Collections.Generic.List[string]]::new()
$skip = $false
foreach($line in $lines) {
  if($line.Trim() -eq $begin) { $skip=$true; continue }
  if($line.Trim() -eq $end) { $skip=$false; continue }
  if(-not $skip) { $out.Add($line) }
}
$out.Add($begin)
$out.Add("$ServerMain cover-api.test cover-h2.test cover-h3.test doh-relay.test doq-resolver.test mqtt-broker.test synthetic-api.test echo.test")
$out.Add("$ServerWss cover-ws.test")
$out.Add("$ServerFront edge-front.test edge-ws.test cdn-front.test workers-front.test graph-front.test telegram-front.test resolver-front.test plain-front.test")
$out.Add("$Resolver stage-m-resolver.test")
$out.Add($end)
Set-Content -Path $path -Value $out -Encoding ascii
if(-not (Resolve-DnsName cover-api.test -ErrorAction SilentlyContinue)) { throw "cover-api.test did not resolve" }
Write-Output "coverlab Windows client hosts configured"
