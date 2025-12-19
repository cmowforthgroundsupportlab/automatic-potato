# TELTONIKA_FULL v1.5 (Production, Old-Windows Safe, Stage2 .NET, Email)
$ErrorActionPreference = "Stop"

# =========================
# PATHS & LOGGING
# =========================
$BaseDir     = "C:\ProgramData\Teltonika"
$LogDir      = Join-Path $BaseDir "Logs"
$LogFile     = Join-Path $LogDir "teltonika-pingreboot.log"
$ScriptDir   = Join-Path $BaseDir "Scripts"
$SuccessFlag = Join-Path $BaseDir "success.flag"
$FailFlag    = Join-Path $BaseDir "fail.flag"

New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
New-Item -ItemType Directory -Path $ScriptDir -Force | Out-Null

function Log {
    param([string]$Msg)
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Msg"
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
    Write-Output $line
}

Log "=== Start (Teltonika Ping Reboot Apply) ==="
Log ("Running as: " + (whoami))

# =========================
# EMAIL REPORTING
# =========================
$EnableEmail = $true

$SmtpServer = "smtp.gmail.com"
$SmtpPort   = 587
$SmtpUser   = "chrismowforth1992@gmail.com"      
$SmtpPass   = "toixkuymjhwntjoi"          
$MailTo     = "cmowforth@groundsupportlabs.com"

function Send-ReportEmail {
    param(
        [string]$Subject,
        [string]$Body
    )
    if (-not $EnableEmail) { return }

    try {
        $securePass = ConvertTo-SecureString $SmtpPass -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential($SmtpUser, $securePass)

        Send-MailMessage `
            -SmtpServer $SmtpServer `
            -Port $SmtpPort `
            -UseSsl `
            -Credential $cred `
            -From $SmtpUser `
            -To $MailTo `
            -Subject $Subject `
            -Body $Body `
            -ErrorAction Stop

        Log "Email report sent"
    }
    catch {
        Log ("WARN: Email failed: " + $_.Exception.Message)
    }
}

# =========================
# CONFIG
# =========================
$RouterPassword        = "GSLali6ht71#"

# Desired router settings
$DesiredEnable         = 1
$DesiredIntervalMin    = 5
$DesiredTimeoutSec     = 10
$DesiredIntervalCount  = 5   # we also map retry to this for GUI consistency

# SharePoint/OneDrive links (must be "Anyone with link")
$PoshShareUrl   = "https://groundsupport-my.sharepoint.com/:u:/g/personal/cmowforth_groundsupportlabs_com/IQA7R7muGbDCTqVFdcmXVDcPAdddxo-jS7RZgB_IFMgt9go?e=93JN8p"
$DotNetShareUrl = "https://groundsupport-my.sharepoint.com/:u:/g/personal/cmowforth_groundsupportlabs_com/IQCfVFScSZZDS4I2zt1rwTA5AR__pbALgQa1KisWJC9ac9s?e=LvmVVm"

$ModuleName = "Posh-SSH"
$ModuleRoot = "C:\Program Files\WindowsPowerShell\Modules"

# Stage2 task
$Stage2Path = Join-Path $BaseDir "stage2.ps1"
$TaskName   = "TeltonikaPingRebootStage2"
$ThisScript = $MyInvocation.MyCommand.Definition

# =========================
# HELPERS
# =========================
function To-DirectDownloadUrl {
    param([string]$u)
    if (-not $u) { return $u }
    if ($u -match '(?i)([?&]download=1)') { return $u }
    if ($u -match '\?') { return ($u + "&download=1") }
    return ($u + "?download=1")
}

$PoshZipUrl = To-DirectDownloadUrl $PoshShareUrl
$DotNetUrl  = To-DirectDownloadUrl $DotNetShareUrl

# TLS 1.2 best-effort
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
try { [Net.ServicePointManager]::Expect100Continue = $false } catch {}

function Test-NetStandard {
    try { [void][System.Reflection.Assembly]::Load("netstandard"); return $true } catch {}
    $paths = @(
        "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\netstandard.dll",
        "$env:WINDIR\Microsoft.NET\Framework\v4.0.30319\netstandard.dll"
    )
    foreach($p in $paths){
        if (Test-Path $p){
            try { [void][System.Reflection.Assembly]::LoadFrom($p); return $true } catch {}
        }
    }
    return $false
}

function Get-FileHeaderHex {
    param([string]$Path, [int]$Bytes = 2)
    $fs = [System.IO.File]::OpenRead($Path)
    try {
        $buf = New-Object byte[] $Bytes
        $read = $fs.Read($buf,0,$Bytes)
        if ($read -lt $Bytes) { return "" }
        return ([BitConverter]::ToString($buf)).Replace("-","")
    }
    finally { $fs.Dispose() }
}

function Assert-ValidDownload {
    param(
        [string]$Path,
        [ValidateSet("zip","exe")] [string]$Type,
        [int64]$MinBytes
    )
    if (-not (Test-Path $Path)) { throw "Downloaded file missing: $Path" }
    $len = (Get-Item $Path).Length
    Log "Downloaded bytes=$len"
    if ($len -lt $MinBytes) { throw "Downloaded file too small ($len bytes). Likely HTML/redirect/auth." }

    $hdr = Get-FileHeaderHex -Path $Path -Bytes 2
    if ($Type -eq "zip" -and $hdr -ne "504B") { throw "Downloaded file is not a ZIP (missing PK). Likely HTML/auth page." }
    if ($Type -eq "exe" -and $hdr -ne "4D5A") { throw "Downloaded file is not an EXE (missing MZ). Likely HTML/auth page." }
}

function Download-WithBITS {
    param([string]$Url,[string]$OutFile,[int]$TimeoutSec)
    Log "BITS: starting (timeout ${TimeoutSec}s)"
    $tmp = "$OutFile.tmp.$PID.bits"
    if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }

    try {
        $job = Start-BitsTransfer -Source $Url -Destination $tmp -Asynchronous -Priority Foreground -ErrorAction Stop
        if (-not $job -or -not $job.Id) { throw "BITS returned null job (not usable on this machine)" }

        $sw = [Diagnostics.Stopwatch]::StartNew()
        while ($true) {
            $j = Get-BitsTransfer -Id $job.Id -ErrorAction Stop
            if ($j.JobState -eq "Transferred") {
                Complete-BitsTransfer -BitsJob $j -ErrorAction Stop
                Move-Item $tmp $OutFile -Force
                Log "BITS: completed"
                return $true
            }
            if ($j.JobState -in @("Error","TransientError","Cancelled")) {
                try { Remove-BitsTransfer -BitsJob $j -Confirm:$false -ErrorAction SilentlyContinue } catch {}
                throw "BITS failed: state=$($j.JobState)"
            }
            if ($sw.Elapsed.TotalSeconds -ge $TimeoutSec) {
                try { Remove-BitsTransfer -Id $job.Id -Confirm:$false -ErrorAction SilentlyContinue } catch {}
                throw "BITS timeout after ${TimeoutSec}s"
            }
            Start-Sleep -Seconds 2
        }
    }
    catch {
        if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
        throw
    }
}

function Download-WithWebClient {
    param([string]$Url,[string]$OutFile,[int]$TimeoutSec)
    Log "WebClient: starting"
    $tmp = "$OutFile.tmp.$PID.wc"
    if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }

    $wc = New-Object System.Net.WebClient
    try {
        $wc.Headers["User-Agent"] = "Mozilla/5.0"
        $wc.DownloadFile($Url, $tmp)
        Move-Item $tmp $OutFile -Force
        Log "WebClient: completed"
        return $true
    }
    finally {
        $wc.Dispose()
        if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
    }
}

function Download-WithIWR {
    param([string]$Url,[string]$OutFile,[int]$TimeoutSec)
    if (-not (Get-Command Invoke-WebRequest -ErrorAction SilentlyContinue)) {
        throw "Invoke-WebRequest not available on this PowerShell"
    }
    Log "Invoke-WebRequest: starting (timeout ${TimeoutSec}s)"
    $tmp = "$OutFile.tmp.$PID.iwr"
    if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }

    # NOTE: No "-Force" here (some PS versions don't support it)
    $job = Start-Job -ArgumentList $Url,$tmp -ScriptBlock {
        param($u,$o)
        try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
        Invoke-WebRequest -Uri $u -OutFile $o -UseBasicParsing -MaximumRedirection 5 -ErrorAction Stop
    }

    if (-not (Wait-Job $job -Timeout $TimeoutSec)) {
        try { Stop-Job $job -Force | Out-Null } catch {}
        try { Remove-Job $job -Force | Out-Null } catch {}
        throw "IWR timeout after ${TimeoutSec}s"
    }

    try { Receive-Job $job -ErrorAction Stop | Out-Null } finally { try { Remove-Job $job -Force | Out-Null } catch {} }

    Move-Item $tmp $OutFile -Force
    Log "Invoke-WebRequest: completed"
    return $true
}

function Download-FileSmart {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$OutFile,
        [ValidateSet("zip","exe")][string]$Type,
        [int64]$MinBytes,
        [int]$Retries = 3
    )

    for ($i=1; $i -le $Retries; $i++) {
        Log "Download attempt $i/$Retries -> $OutFile"
        if (Test-Path $OutFile) { Remove-Item $OutFile -Force -ErrorAction SilentlyContinue }

        # Each attempt uses fresh file path (avoid lock issues)
        try {
            try {
                Download-WithBITS -Url $Url -OutFile $OutFile -TimeoutSec 120 | Out-Null
                Assert-ValidDownload -Path $OutFile -Type $Type -MinBytes $MinBytes
                return $true
            } catch {
                Log ("BITS failed: " + $_.Exception.Message)
            }

            try {
                Download-WithWebClient -Url $Url -OutFile $OutFile -TimeoutSec 240 | Out-Null
                Assert-ValidDownload -Path $OutFile -Type $Type -MinBytes $MinBytes
                return $true
            } catch {
                Log ("WebClient failed: " + $_.Exception.Message)
            }

            try {
                Download-WithIWR -Url $Url -OutFile $OutFile -TimeoutSec 240 | Out-Null
                Assert-ValidDownload -Path $OutFile -Type $Type -MinBytes $MinBytes
                return $true
            } catch {
                Log ("IWR failed: " + $_.Exception.Message)
            }

        } catch {
            Log ("Attempt failed: " + $_.Exception.Message)
        }

        Start-Sleep -Seconds (5*$i)
    }

    return $false
}

function Escape-ForShSingleQuote {
    param([string]$s)
    # In sh: ' -> '"'"'
    return ($s -replace "'", "'""'""'")
}

# =========================
# ROUTER IP
# =========================
$RouterIp = (Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway } | Select-Object -First 1).IPv4DefaultGateway.NextHop
if (-not $RouterIp) {
    Log "ERROR: Could not determine router IP"
    New-Item $FailFlag -Force | Out-Null
    throw "No router IP"
}
Log "Router IP detected: $RouterIp"

# =========================
# .NET 4.8 (Stage2 if missing netstandard)
# =========================
if (-not (Test-NetStandard)) {
    Log "NetStandard missing. Installing .NET Framework 4.8 then rebooting for Stage2..."

    $exe = "C:\ProgramData\ndp48.exe"
    $ok = Download-FileSmart -Url $DotNetUrl -OutFile $exe -Type exe -MinBytes 5000000 -Retries 3
    if (-not $ok) { throw "Failed to download after retries: $exe" }

    Log "Launching .NET 4.8 installer..."
    $p = Start-Process -FilePath $exe -ArgumentList "/q /norestart" -PassThru
    $p.WaitForExit()
    Log ("DotNet installer exit code: " + $p.ExitCode)

    Log "Creating Stage2 task and rebooting..."
@"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$ThisScript"
"@ | Out-File -FilePath $Stage2Path -Encoding UTF8 -Force

    schtasks /Create /TN $TaskName /SC ONSTART /RU SYSTEM /RL HIGHEST /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$Stage2Path`"" /F | Out-Null
    Restart-Computer -Force
    exit 0
}

# =========================
# POSH-SSH (ensure installed)
# =========================
Log ("PSModulePath: " + $env:PSModulePath)

try { Import-Module Posh-SSH -Force -ErrorAction Stop; Log "Posh-SSH imported" }
catch {
    Log "Posh-SSH not importable - attempting offline install"

    $zip = "C:\ProgramData\Posh-SSH.zip"
    $ok = Download-FileSmart -Url $PoshZipUrl -OutFile $zip -Type zip -MinBytes 1000000 -Retries 3
    if (-not $ok) { throw "Failed to download Posh-SSH.zip" }

    $stage = Join-Path $BaseDir "posh_stage"
    if (Test-Path $stage) { Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Path $stage -Force | Out-Null

    Log "Extracting Posh-SSH.zip -> $stage"
    Expand-Archive -Path $zip -DestinationPath $stage -Force

    # Find module folder
    $found = Get-ChildItem -Path $stage -Recurse -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq "Posh-SSH" } | Select-Object -First 1
    if (-not $found) { throw "Could not find Posh-SSH folder inside zip" }

    $dest = Join-Path $ModuleRoot "Posh-SSH"
    if (Test-Path $dest) { Remove-Item $dest -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Path $ModuleRoot -Force | Out-Null

    Log "Installing module folder -> $dest"
    Copy-Item -Path $found.FullName -Destination $dest -Recurse -Force

    Import-Module Posh-SSH -Force -ErrorAction Stop
    Log "Posh-SSH imported"
}

# =========================
# CONNECTIVITY CHECK
# =========================
$tnc = Test-NetConnection -ComputerName $RouterIp -Port 22 -WarningAction SilentlyContinue
Log ("Port 22 reachable: " + $tnc.TcpTestSucceeded)
if (-not $tnc.TcpTestSucceeded) { throw "SSH port 22 not reachable" }

# =========================
# SSH APPLY (read -> choose section -> apply -> verify)
# =========================
$Outcome  = "FAIL"
$ExitCode = 1

try {
    $cred = New-Object PSCredential("root",(ConvertTo-SecureString $RouterPassword -AsPlainText -Force))

    Log "Opening SSH session..."
    $session = New-SSHSession -ComputerName $RouterIp -Credential $cred -AcceptKey -ErrorAction Stop
    Log "SSH session established."

    Log "Reading current ping_reboot config..."
    $preCmd = "sh -lc 'uci show ping_reboot 2>/dev/null; echo ---; cat /etc/config/ping_reboot 2>/dev/null'"
    $pre = Invoke-SSHCommand -SSHSession $session -Command $preCmd -ErrorAction Stop
    $preOut = ($pre.Output -join "`n")
    Log ("Router pre-state:`n" + $preOut)

    # Pick section index: choose the most populated section
    $sectionIndex = 0
    $count0 = ([regex]::Matches($preOut, "ping_reboot\.@ping_reboot\[0\]\.")).Count
    $count1 = ([regex]::Matches($preOut, "ping_reboot\.@ping_reboot\[1\]\.")).Count
    if ($count1 -gt $count0) { $sectionIndex = 1 }
    Log "Selected ping_reboot section index: $sectionIndex"

    $sec = "ping_reboot.@ping_reboot[$sectionIndex]"

    # Detect timeout key preference
    $timeoutKey = "time_out"
    if ($preOut -match ([regex]::Escape($sec) + "\.timeout=")) { $timeoutKey = "timeout" }
    Log "Timeout key selected: $timeoutKey"

    # Build router-side script (POSIX shell), then sh -lc it safely
    $sh = @"
set -e
sec='$sec'
uci set \$sec.enable='$DesiredEnable'
uci set \$sec.interval='$DesiredIntervalMin'
uci set \$sec.time='$DesiredIntervalMin'
uci set \$sec.interval_count='$DesiredIntervalCount'
uci set \$sec.retry='$DesiredIntervalCount'
uci set \$sec.$timeoutKey='$DesiredTimeoutSec'
# also set both timeout keys for future-proofing (harmless)
uci set \$sec.timeout='$DesiredTimeoutSec' 2>/dev/null || true
uci set \$sec.time_out='$DesiredTimeoutSec' 2>/dev/null || true
uci commit ping_reboot
if [ -x /etc/init.d/ping_reboot ]; then /etc/init.d/ping_reboot restart; fi
uci show ping_reboot
"@ -replace "`r",""

    $escaped = Escape-ForShSingleQuote $sh
    $applyCmd = "sh -lc '$escaped'"

    Log "Applying settings via SSH..."
    $result = Invoke-SSHCommand -SSHSession $session -Command $applyCmd -ErrorAction Stop
    $out = ($result.Output -join "`n")
    Log ("Router output:`n" + $out)

    Remove-SSHSession -SSHSession $session | Out-Null

    # Verify
    $ok =
        ($out -match "enable='1'") -and
        ($out -match "interval='5'") -and
        ($out -match "interval_count='5'") -and
        ($out -match "retry='5'") -and
        ($out -match "(time_out|timeout)='10'")

    if (-not $ok) { throw "Verification failed" }

    Log "SUCCESS: Ping reboot enabled and values set on $RouterIp"
    Set-Content -Path $SuccessFlag -Value "$(Get-Date -Format s) $RouterIp"
    if (Test-Path $FailFlag) { Remove-Item $FailFlag -Force -ErrorAction SilentlyContinue }

    # Remove Stage2 task if present
    try { schtasks /Delete /TN $TaskName /F | Out-Null } catch {}

    $Outcome  = "SUCCESS"
    $ExitCode = 0
}
catch {
    Log ("ERROR: Exception: " + $_.Exception.Message)
    New-Item $FailFlag -Force | Out-Null
    $Outcome  = "FAIL"
    if ($ExitCode -eq 0) { $ExitCode = 1 }
}
finally {
    try {
        $tail = (Get-Content $LogFile -Tail 80 | Out-String)
        $ipForSubject = if ($RouterIp) { $RouterIp } else { "no-router-ip" }

        if (Test-Path $SuccessFlag) {
            Send-ReportEmail -Subject ("TELTONIKA SUCCESS - {0} - {1}" -f $env:COMPUTERNAME, $ipForSubject) -Body $tail
        } else {
            Send-ReportEmail -Subject ("TELTONIKA FAIL - {0} - {1}" -f $env:COMPUTERNAME, $ipForSubject) -Body $tail
        }
    } catch {
        Log ("WARN: Email block failed: " + $_.Exception.Message)
    }

    Log "=== End ($Outcome) ==="
}

exit $ExitCode
