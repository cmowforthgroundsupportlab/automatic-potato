# ==============================
# GSL PixelWatchdog V2 - Deploy Probe + Create Tasks (v11.1 - SILENT: wscript actions, no CMD flash)
# - Probe task: INTERACTIVE group (SID S-1-5-4), runs wscript.exe -> RunProbeHidden.vbs -> EXE (hidden)
# - Sync task : SYSTEM (SID S-1-5-18), runs wscript.exe -> RunSyncHidden.vbs -> powershell.exe -File SyncStatusToHKLM.ps1 (hidden)
# - Uses Register-ScheduledTask -Xml (reliable on estate)
# - No reliance on any local username/password
# - SyncStatusToHKLM.ps1 v2.0.0: adds FrozenEligibleSeconds + normalizes AlertEligible (effective eligibility) + writes SyncVersion
# - Hardened download: TLS12 + timeouts + BITS fallback + transcript log
# ==============================

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Force TLS 1.2 (helps with some .NET defaults / environments)
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

# ---- CONFIG ----
$ZipUrl   = "https://github.com/cmowforthgroundsupportlab/automatic-potato/releases/download/PixelWatchdog_v2/GSL_PixelWatchdogProbe.zip"

$WorkDir  = "C:\ProgramData\GSL\PixelWatchdog\_deploy"
$StateDir = "C:\ProgramData\GSL\PixelWatchdog"

$BaseDir  = "C:\Program Files\GSL\PixelWatchdog"
$ProbeDir = Join-Path $BaseDir "probe"
$SyncPs1  = Join-Path $BaseDir "SyncStatusToHKLM.ps1"

$TaskProbeName = "GSL PixelWatchdog Probe"
$TaskSyncName  = "GSL PixelWatchdog Sync"
# --------------

# Log (Transcript)
$DeployLog = Join-Path $WorkDir "deploy.log"

# Embedded sync script content (SYSTEM-safe JSON->HKLM bridge) + SyncUtc heartbeat
$SyncScriptContent = @'
# ==============================
# GSL PixelWatchdog - Sync JSON status -> HKLM scalars (SYSTEM-safe)
# SyncStatusToHKLM.ps1 Version: 2.0.0
# - Adds FrozenEligibleSeconds
# - Normalizes AlertEligible to "effective eligibility"
# ==============================

$ErrorActionPreference = "Stop"

$statusPath = "C:\ProgramData\GSL\PixelWatchdog\status.json"
$regPath    = "HKLM:\Software\GSL\PixelWatchdog"

function Set-RegSz($name, $value) {
  New-ItemProperty -Path $regPath -Name $name -Value ([string]$value) -PropertyType String -Force | Out-Null
}
function Set-RegDword($name, $value) {
  $v = 0
  if ($null -ne $value -and $value -ne "") { $v = [int]$value }
  New-ItemProperty -Path $regPath -Name $name -Value $v -PropertyType DWord -Force | Out-Null
}

try {
  New-Item -Path $regPath -Force | Out-Null
  Set-RegSz "SyncUtc" ([DateTime]::UtcNow.ToString("o"))
  Set-RegSz "SyncVersion" "2.0.0"

  if (-not (Test-Path $statusPath)) {
    Set-RegSz    "State" "NO_DATA"
    Set-RegDword "FrozenSeconds" 0
    Set-RegDword "FrozenEligibleSeconds" 0
    Set-RegDword "ExceptionActive" 0
    Set-RegDword "AlertEligible" 0
    Set-RegSz    "ExceptionReason" ""
    Set-RegSz    "IncidentId" ""
    Set-RegSz    "SampleUtc" ""
    Set-RegSz    "Computer" $env:COMPUTERNAME
    Set-RegSz    "Location" ""
    Write-Output "STATUS=NO_DATA status.json missing"
    exit 0
  }

  $raw = Get-Content -Path $statusPath -Raw -ErrorAction Stop
  $s = $raw | ConvertFrom-Json -ErrorAction Stop

  Set-RegSz    "State"          $s.State
  Set-RegDword "FrozenSeconds"  $s.FrozenSeconds
  Set-RegSz    "IncidentId"     $s.IncidentId
  Set-RegSz    "LastMotionUtc"  $s.LastMotionUtc
  Set-RegSz    "FrozenSinceUtc" $s.FrozenSinceUtc
  Set-RegDword "HashDelta"      $s.HashDelta
  Set-RegSz    "SampleUtc"      $s.SampleUtc
  Set-RegSz    "SnapshotPath"   $s.SnapshotPath

  $excActive = 0
  if ($s.ExceptionActive -eq $true -or $s.ExceptionActive -eq 1 -or ([string]$s.ExceptionActive).ToLowerInvariant() -eq "true") { $excActive = 1 }
  Set-RegDword "ExceptionActive" $excActive
  Set-RegSz    "ExceptionReason" $s.ExceptionReason

  # ------------------------------
  # NORMALIZED ELIGIBILITY + FrozenEligibleSeconds
  # HKLM AlertEligible reflects EFFECTIVE eligibility:
  #   State=FROZEN AND ExceptionActive=0 AND Probe says eligible
  # FrozenEligibleSeconds tracks FrozenSeconds only when effectively eligible.
  # ------------------------------
  $eligibleRaw = 0
  if ($s.AlertEligible -eq $true -or $s.AlertEligible -eq 1 -or ([string]$s.AlertEligible).ToLowerInvariant() -eq "true") { $eligibleRaw = 1 }

  $stateStr = ""
  if ($null -ne $s.State) { $stateStr = ([string]$s.State) }
  $isFrozen = ($stateStr.ToUpperInvariant() -eq "FROZEN")

  $eligibleEffective = 0
  if ($isFrozen -and $eligibleRaw -eq 1 -and $excActive -eq 0) { $eligibleEffective = 1 }

  Set-RegDword "AlertEligible" $eligibleEffective

  $fes = 0
  if ($eligibleEffective -eq 1) {
    if ($null -ne $s.FrozenSeconds -and $s.FrozenSeconds -ne "") { $fes = [int]$s.FrozenSeconds }
  }
  Set-RegDword "FrozenEligibleSeconds" $fes

  if ($s.PSObject.Properties.Name -contains "Computer") { Set-RegSz "Computer" $s.Computer } else { Set-RegSz "Computer" $env:COMPUTERNAME }
  if ($s.PSObject.Properties.Name -contains "Location") { Set-RegSz "Location" $s.Location } else { Set-RegSz "Location" "" }

  Write-Output "STATUS=OK Synced status.json -> HKLM"
  exit 0
}
catch {
  $msg = $_.Exception.Message
  New-Item -Path $regPath -Force | Out-Null
  Set-RegSz "State" "ERROR"
  Set-RegSz "LastError" $msg
  Set-RegSz "SyncUtc" ([DateTime]::UtcNow.ToString("o"))
  Set-RegSz "SyncVersion" "2.0.0"
  Set-RegDword "AlertEligible" 0
  Set-RegDword "FrozenEligibleSeconds" 0
  Write-Output "STATUS=ERROR $msg"
  exit 0
}
'@

function Ensure-Dir([string]$p) {
  New-Item -ItemType Directory -Path $p -Force -ErrorAction SilentlyContinue | Out-Null
}

function Download-File([string]$url, [string]$dest) {
  Write-Output "STEP=DOWNLOAD URL=$url DEST=$dest"

  # Attempt 1: Invoke-WebRequest with hard timeout
  try {
    Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop
    Write-Output "STEP=DOWNLOAD RESULT=IWR_OK"
    return
  }
  catch {
    Write-Output "STEP=DOWNLOAD RESULT=IWR_FAIL MSG=$($_.Exception.Message)"
  }

  # Attempt 2: BITS with hard timeout (async + polling)
  $job = $null
  try {
    Write-Output "STEP=DOWNLOAD RESULT=TRY_BITS"
    $job = Start-BitsTransfer -Source $url -Destination $dest -Asynchronous -ErrorAction Stop
    $sw = [Diagnostics.Stopwatch]::StartNew()

    while ($true) {
      $j = Get-BitsTransfer -Id $job.Id -ErrorAction SilentlyContinue
      if (-not $j) { throw "BITS job disappeared" }

      if ($j.JobState -eq "Transferred") {
        Complete-BitsTransfer -BitsJob $j -ErrorAction Stop
        Write-Output "STEP=DOWNLOAD RESULT=BITS_OK"
        break
      }

      if ($j.JobState -in @("Error","TransientError","Cancelled")) {
        throw "BITS state=$($j.JobState) error=$($j.ErrorDescription)"
      }

      if ($sw.Elapsed.TotalSeconds -gt 120) {
        Remove-BitsTransfer -BitsJob $j -Confirm:$false -ErrorAction SilentlyContinue
        throw "BITS timeout after 120s"
      }

      Start-Sleep -Seconds 2
    }
  }
  catch {
    if ($job) { Remove-BitsTransfer -BitsJob $job -Confirm:$false -ErrorAction SilentlyContinue }
    throw "STEP=DOWNLOAD MSG=$($_.Exception.Message)"
  }
}

function Write-TextUtf8([string]$path, [string]$content) {
  Ensure-Dir (Split-Path -Parent $path)
  Set-Content -Path $path -Value $content -Encoding UTF8 -Force
}

function Remove-TaskIfExists([string]$name) {
  try {
    $t = Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskName -eq $name } | Select-Object -First 1
    if ($t) { Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -Confirm:$false -ErrorAction Stop | Out-Null }
  } catch { }
}

function XmlEscape([string]$s) {
  if ($null -eq $s) { return "" }
  return ($s.Replace("&","&amp;").Replace("<","&lt;").Replace(">","&gt;").Replace('"',"&quot;").Replace("'","&apos;"))
}

function New-RepeatingOnceTriggerXml([DateTime]$startUtc, [string]$interval, [string]$duration) {
  $iso = $startUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
@"
<TimeTrigger>
  <StartBoundary>$iso</StartBoundary>
  <Enabled>true</Enabled>
  <Repetition>
    <Interval>$interval</Interval>
    <Duration>$duration</Duration>
    <StopAtDurationEnd>false</StopAtDurationEnd>
  </Repetition>
</TimeTrigger>
"@
}

function New-TaskXml([string]$author, [string]$desc, [string]$principalXml, [string]$command, [string]$arguments, [string]$triggerXml, [bool]$hidden) {
  $h = if ($hidden) { "true" } else { "false" }
  $commandEsc   = XmlEscape $command
  $argumentsEsc = XmlEscape $arguments
@"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>$(XmlEscape $author)</Author>
    <Description>$(XmlEscape $desc)</Description>
  </RegistrationInfo>
  <Triggers>
    $triggerXml
  </Triggers>
  <Principals>
    $principalXml
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>$h</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>$commandEsc</Command>
      <Arguments>$argumentsEsc</Arguments>
    </Exec>
  </Actions>
</Task>
"@
}

try {
  Ensure-Dir $WorkDir
  Ensure-Dir $StateDir
  Ensure-Dir $BaseDir
  Ensure-Dir $ProbeDir

  # Start transcript after WorkDir exists
  try {
    Start-Transcript -Path $DeployLog -Append | Out-Null
    Write-Output "STEP=TRANSCRIPT PATH=$DeployLog"
  } catch { }

  Import-Module ScheduledTasks -ErrorAction Stop

  # --- Download & Extract ---
  $zipPath = Join-Path $WorkDir "GSL_PixelWatchdogProbe.zip"
  $extract = Join-Path $WorkDir "extracted"

  Write-Output "STEP=DOWNLOAD_BEGIN"
  Download-File -url $ZipUrl -dest $zipPath
  Write-Output "STEP=DOWNLOAD_DONE"

  if (-not (Test-Path $zipPath)) { throw "STEP=DOWNLOAD MSG=Zip missing after download: $zipPath" }

  Write-Output "STEP=EXTRACT_BEGIN ZIP=$zipPath DEST=$extract"
  if (Test-Path $extract) { Remove-Item $extract -Recurse -Force -ErrorAction SilentlyContinue }
  Ensure-Dir $extract
  Expand-Archive -Path $zipPath -DestinationPath $extract -Force
  Write-Output "STEP=EXTRACT_DONE"

  $exeCandidate1 = Join-Path $extract "pixel_watchdog_probe.exe"
  $exeCandidate2 = Join-Path $extract "pixel_watchdog_probe\pixel_watchdog_probe.exe"

  Write-Output "STEP=PROBE_COPY_BEGIN"
  if (Test-Path $exeCandidate2) { robocopy (Join-Path $extract "pixel_watchdog_probe") $ProbeDir /E /NFL /NDL /NJH /NJS /NP | Out-Null }
  elseif (Test-Path $exeCandidate1) { robocopy $extract $ProbeDir /E /NFL /NDL /NJH /NJS /NP | Out-Null }
  else { throw "STEP=ZIP_LAYOUT MSG=Could not find pixel_watchdog_probe.exe in extracted content." }
  Write-Output "STEP=PROBE_COPY_DONE"

  $probeExe = Join-Path $ProbeDir "pixel_watchdog_probe.exe"
  if (-not (Test-Path $probeExe)) { throw "STEP=PROBE_COPY MSG=Probe EXE missing after copy: $probeExe" }

  # --- Write/Upgrade Sync script (idempotent) ---
  Write-Output "STEP=SYNC_SCRIPT_BEGIN PATH=$SyncPs1"
  $needSyncUpgrade = $true
  if (Test-Path $SyncPs1) {
    try {
      $existing = Get-Content -Path $SyncPs1 -Raw -ErrorAction Stop
      if ($existing -match 'SyncStatusToHKLM\.ps1 Version:\s*2\.0\.0' -and
          $existing -match 'FrozenEligibleSeconds' -and
          $existing -match 'eligibleEffective') {
        $needSyncUpgrade = $false
      }
    } catch { $needSyncUpgrade = $true }
  }

  if ($needSyncUpgrade) {
    Write-TextUtf8 -path $SyncPs1 -content $SyncScriptContent
    Write-Output "STEP=SYNC_SCRIPT_RESULT=WRITTEN"
  } else {
    Write-Output "STEP=SYNC_SCRIPT_RESULT=SKIPPED_ALREADY_CURRENT"
  }

  if (-not (Test-Path $SyncPs1)) { throw "STEP=SYNC_SCRIPT MSG=Sync script missing after write: $SyncPs1" }
  Write-Output "STEP=SYNC_SCRIPT_DONE"

  # --- Probe launcher INI ---
  $iniPath = Join-Path $StateDir "probe_launcher.ini"
  @($probeExe, $ProbeDir) | Set-Content -Path $iniPath -Encoding ASCII -Force

  # --- Probe VBS (hidden) ---
  $probeVbsPath = Join-Path $StateDir "RunProbeHidden.vbs"
@'
On Error Resume Next
Set fso = CreateObject("Scripting.FileSystemObject")
cfg = "C:\ProgramData\GSL\PixelWatchdog\probe_launcher.ini"
If Not fso.FileExists(cfg) Then WScript.Quit 2 End If
Set ts = fso.OpenTextFile(cfg, 1, False)
exePath = ts.ReadLine
workDir = ts.ReadLine
ts.Close
Set sh = CreateObject("WScript.Shell")
sh.CurrentDirectory = workDir
sh.Run """" & exePath & """", 0, False
WScript.Quit 0
'@ | Set-Content -Path $probeVbsPath -Encoding ASCII -Force

  if (-not (Test-Path $probeVbsPath)) { throw "STEP=VBS_PROBE_CREATE MSG=Failed to create: $probeVbsPath" }

  # --- Sync VBS (hidden) ---
  $syncVbsPath = Join-Path $StateDir "RunSyncHidden.vbs"
@'
On Error Resume Next
Set sh = CreateObject("WScript.Shell")
cmd = "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File ""C:\Program Files\GSL\PixelWatchdog\SyncStatusToHKLM.ps1"""
sh.Run cmd, 0, False
WScript.Quit 0
'@ | Set-Content -Path $syncVbsPath -Encoding ASCII -Force

  if (-not (Test-Path $syncVbsPath)) { throw "STEP=VBS_SYNC_CREATE MSG=Failed to create: $syncVbsPath" }

  # --- Remove old tasks ---
  Remove-TaskIfExists $TaskProbeName
  Remove-TaskIfExists $TaskSyncName

  # Trigger starts 1 minute from now (UTC), repeats every minute for ~10 years
  $startUtc   = [DateTime]::UtcNow.AddMinutes(1)
  $triggerXml = New-RepeatingOnceTriggerXml -startUtc $startUtc -interval "PT1M" -duration "P3650D"

  # Principals
  $probePrincipalXml = @'
<Principal id="Author">
  <GroupId>S-1-5-4</GroupId>
  <RunLevel>HighestAvailable</RunLevel>
</Principal>
'@

  $syncPrincipalXml = @'
<Principal id="Author">
  <UserId>S-1-5-18</UserId>
  <RunLevel>HighestAvailable</RunLevel>
</Principal>
'@

  $wscript = "$env:SystemRoot\System32\wscript.exe"
  $probeArgs = '"' + $probeVbsPath + '"'
  $syncArgs  = '"' + $syncVbsPath  + '"'

  $author = "GSL"

  # Hidden=true here also hides them from casual view in Task Scheduler UI (optional but helpful)
  $probeXml = New-TaskXml -author $author -desc "GSL PixelWatchdog Probe (silent)" -principalXml $probePrincipalXml -command $wscript -arguments $probeArgs -triggerXml $triggerXml -hidden $true
  $syncXml  = New-TaskXml -author $author -desc "GSL PixelWatchdog Sync (silent)"  -principalXml $syncPrincipalXml  -command $wscript -arguments $syncArgs  -triggerXml $triggerXml -hidden $true

  try { Register-ScheduledTask -TaskName $TaskProbeName -Xml $probeXml -Force -ErrorAction Stop | Out-Null }
  catch { throw "STEP=REGISTER_PROBE MSG=$($_.Exception.Message)" }

  try { Register-ScheduledTask -TaskName $TaskSyncName  -Xml $syncXml  -Force -ErrorAction Stop | Out-Null }
  catch { throw "STEP=REGISTER_SYNC MSG=$($_.Exception.Message)" }

  # Verify + prime run
  $probeFound = Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskName -eq $TaskProbeName } | Select-Object -First 1
  if (-not $probeFound) { throw "STEP=VERIFY_PROBE MSG=Probe task not found after XML registration. name=$TaskProbeName" }

  $syncFound = Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskName -eq $TaskSyncName } | Select-Object -First 1
  if (-not $syncFound) { throw "STEP=VERIFY_SYNC MSG=Sync task not found after XML registration. name=$TaskSyncName" }

  try { Start-ScheduledTask -TaskName $TaskProbeName -ErrorAction Stop } catch { throw "STEP=RUN_PROBE MSG=$($_.Exception.Message)" }
  Start-Sleep -Seconds 2
  try { Start-ScheduledTask -TaskName $TaskSyncName  -ErrorAction Stop } catch { throw "STEP=RUN_SYNC MSG=$($_.Exception.Message)" }

  Write-Output "STATUS=SUCCESS Installed probe + sync tasks (silent, no CMD flash)."

  try { Stop-Transcript | Out-Null } catch {}
  exit 0
}
catch {
  Write-Output "STATUS=ERROR $($_.Exception.Message)"
  try { Stop-Transcript | Out-Null } catch {}
  exit 0
}
