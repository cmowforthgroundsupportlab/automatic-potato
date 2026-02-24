# deploy/bootstrap.ps1
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

$dir = "C:\ProgramData\GSL\PixelWatchdog\_deploy"
New-Item -ItemType Directory -Path $dir -Force | Out-Null

$deployUrl = "https://raw.githubusercontent.com/cmowforthgroundsupportlab/automatic-potato/main/deploy/Deploy-PixelWatchdog.ps1"
$deployPs1 = Join-Path $dir "Deploy-PixelWatchdog.ps1"

Invoke-WebRequest -Uri $deployUrl -OutFile $deployPs1 -UseBasicParsing -TimeoutSec 60

# Validate we didn't download HTML
$head = Get-Content -Path $deployPs1 -TotalCount 10
if (($head -join "`n") -match "<!DOCTYPE html>|<html|AccessDenied|Error") {
  throw "Downloaded HTML/error content instead of Deploy-PixelWatchdog.ps1. URL=$deployUrl"
}

$outLog = Join-Path $dir "deploy_stdout.log"
$errLog = Join-Path $dir "deploy_stderr.log"

$p = Start-Process -FilePath "powershell.exe" -ArgumentList @(
  "-NoProfile","-ExecutionPolicy","Bypass","-File",$deployPs1
) -Wait -PassThru -WindowStyle Hidden -RedirectStandardOutput $outLog -RedirectStandardError $errLog

"BOOTSTRAP_OK ExitCode=$($p.ExitCode)" | Set-Content -Path (Join-Path $dir "bootstrap_result.txt") -Encoding UTF8
exit $p.ExitCode
