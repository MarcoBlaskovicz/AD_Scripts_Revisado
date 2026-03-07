<#
DC Troubleshooting Script (compatible with Windows PowerShell 5.1)

Collects:
- System and network information
- Critical services status
- DCDIAG (full + DNS)
- REPADMIN (replsummary, showrepl, queue, showbackup, showrepl per partner)
- SYSVOL/NETLOGON and DFSR (if available)
- DNS SRV record checks + zones + reverse lookup
- Domain DC discovery and connectivity/port tests
- Event logs (Directory Service, DNS Server, DFS Replication, System, Security)
- AD Database integrity (ntdsutil) + FSMO holders + PDC Emulator connectivity
- Kerberos tickets (klist) + secure channel (nltest /sc_query) + lockout events
- Advanced replication (ISTG, bridgeheads, USN vectors, tombstone lag check)
- GPO health: SYSVOL vs AD consistency, orphaned GPOs
- Security: privileged group membership, audit policy, critical Security events
- OS health: disk space (NTDS + SYSVOL volumes), memory pool, installed hotfixes
- AD Sites and Services: site membership, subnets, site options

Output:
  Report  : C:\Temp\OutputScripts\DC_Troubleshoot_<DC>_<timestamp>.txt
  Log     : C:\Temp\LogScripts\DC_Troubleshoot_<DC>_<timestamp>.log
  (dcdiag separate copies saved in the same output folder)

CHANGELOG:
  v1 - Original script
  v2 - Fixes: UTF8 encoding, dcdiag via call operator, repadmin /replicate removed,
              events filtered by Level, LastBootUpTime from native CIM,
              TCP ports in parallel via runspaces, $ctx instead of global variables
  v3 - Performance improvements (PS 5.1 compatible):
    PERF-1  StreamWriter kept open for all report I/O
    PERF-2  Heavy external commands dispatched in parallel via runspaces
    PERF-3  Event log collection in parallel via runspaces
    PERF-4  Per partner DC: ping + TCP ports + showrepl in parallel via runspaces
  v4 - Paths and logging:
    PATH-1  Output: C:\Temp\OutputScripts\DC_Troubleshoot_<DC>_<timestamp>.txt (single file)
    PATH-2  Log   : C:\Temp\LogScripts\DC_Troubleshoot_<DC>_<timestamp>.log (real-time)
    PATH-3  Parameters -OutputDir and -LogDir added (override defaults)
  v5 - Visual feedback (PS 5.1 compatible):
    VIS-1  Animated spinner with elapsed time during parallel phases
           → displays rotating frame + hh:mm:ss while runspaces are running
    VIS-2  Native PowerShell Write-Progress bar (top of terminal)
           → updated per phase; cleared on completion
    VIS-3  Partner DC progress printed line by line as each DC completes
           → [N/Total] DCNAME  Ping:OK  Ports:X/Y open  Repl:OK
    VIS-4  Final summary table in color on the console
           → each phase with status (OK/WARN/ERROR) and elapsed time
  v6 - Additional troubleshooting coverage:
    NEW-1  AD Database & FSMO: ntdsutil integrity, FSMO holders, PDC Emulator connectivity
    NEW-2  Kerberos & Auth: klist tickets, nltest /sc_query, account lockout events (4740)
    NEW-3  DNS deep-dive: dnscmd statistics/zones, _msdcs records, reverse PTR lookup
    NEW-4  Advanced replication: repadmin /istg /bridgeheads /showutdvec, tombstone lag
    NEW-5  GPO & SYSVOL consistency: SYSVOL vs AD GPO count, orphaned GPO detection
    NEW-6  Security & Audit: privileged group members, auditpol, Security event IDs
    NEW-7  OS health: disk space (NTDS + SYSVOL), memory pool counters, Get-HotFix
    NEW-8  Sites & Subnets: nltest /dsgetsite, repadmin /siteoptions, subnet mapping
#>

[CmdletBinding()]
param(
    [string]$Domain       = "",
    [string[]]$PartnerDCs = @(),
    [string]$OutputDir    = "C:\Temp\OutputScripts",
    [string]$LogDir       = "C:\Temp\LogScripts"
)

Set-StrictMode -Version 2
$ErrorActionPreference = "Continue"

# ============================================================
# PERF-1: StreamWriter — opened once, written N times, closed at the end
# ============================================================
function New-ReportWriter {
    param([string]$Path)
    $sw = New-Object System.IO.StreamWriter($Path, $false, [System.Text.Encoding]::UTF8)
    $sw.AutoFlush = $false
    return $sw
}

function Write-Section {
    param([System.IO.StreamWriter]$Writer, [string]$Title)
    $line  = ("=" * 110)
    $block = ("`r`n{0}`r`n# {1}`r`n{0}`r`n" -f $line, $Title)
    $Writer.Write($block)
    $Writer.Flush()
}

function Write-Text {
    param([System.IO.StreamWriter]$Writer, [string]$Text)
    $Writer.WriteLine($Text)
}

function Write-Block {
    param([System.IO.StreamWriter]$Writer, [string]$Block)
    $Writer.Write($Block)
}

# ============================================================
# General helpers
# ============================================================
function New-DirIfMissing([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Try-GetDomain([string]$DomainParam) {
    if ($DomainParam -and $DomainParam.Trim()) { return $DomainParam.Trim() }
    try {
        $d = (Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).Domain
        if ($d -and $d -ne "WORKGROUP") { return $d }
    } catch {}
    return ""
}

function DomainToNC([string]$Fqdn) {
    if (-not $Fqdn) { return "" }
    return "DC=" + (($Fqdn -split "\.") -join ",DC=")
}

function Command-Exists([string]$Name) {
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Get-LocalIPs {
    try {
        Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -and $_.IPAddress -notlike "169.254*" } |
            Select-Object InterfaceAlias, IPAddress, PrefixLength
    } catch { @() }
}

function Get-DnsServers {
    try {
        Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Select-Object InterfaceAlias, ServerAddresses
    } catch { @() }
}

# ============================================================
# PERF-2 / PERF-3: Generic runspace engine
# VIS-1: Animated spinner + elapsed time while jobs are running
# VIS-2: Write-Progress updated per phase
# ============================================================
function Invoke-ParallelTasks {
    param(
        [object[]]$Tasks,
        [int]$MaxRunspaces  = 8,
        [string]$PhaseLabel = "Processando",   # label for Write-Progress / spinner
        [int]$ProgressId    = 1                # Write-Progress ID (avoids conflicts between calls)
    )

    $pool = [runspacefactory]::CreateRunspacePool(1, $MaxRunspaces)
    $pool.ApartmentState = "MTA"
    $pool.Open()

    $jobs = @()
    foreach ($task in $Tasks) {
        $ps = [powershell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript($task.ScriptBlock)
        $jobs += [pscustomobject]@{ Label = $task.Label; PS = $ps; Handle = $ps.BeginInvoke(); Done = $false }
    }

    $total      = $jobs.Count
    $done       = 0
    $spinFrames = @("|", "/", "-", "\")
    $spinIdx    = 0
    $sw         = [System.Diagnostics.Stopwatch]::StartNew()

    # VIS-2: initial progress bar
    Write-Progress -Id $ProgressId -Activity $PhaseLabel `
        -Status ("Aguardando... 0 / {0} concluídos" -f $total) `
        -PercentComplete 0

    # Polling loop — updates spinner and Write-Progress until all jobs complete
    while ($done -lt $total) {
        foreach ($job in $jobs) {
            if (-not $job.Done -and $job.Handle.IsCompleted) {
                $job.Done = $true
                $done++
            }
        }

        # VIS-1: spinner with elapsed time
        $elapsed  = $sw.Elapsed
        $elapsedStr = ("{0:D2}:{1:D2}:{2:D2}" -f [int]$elapsed.TotalHours, $elapsed.Minutes, $elapsed.Seconds)
        $frame    = $spinFrames[$spinIdx % $spinFrames.Count]
        $spinIdx++
        $pct      = [int](($done / $total) * 100)

        # Write spinner on the same line (no newline)
        $spinLine = ("  {0}  {1}  [{2}/{3}]  {4}" -f $frame, $PhaseLabel, $done, $total, $elapsedStr)
        Write-Host ("`r" + $spinLine.PadRight(80)) -NoNewline -ForegroundColor DarkCyan

        # VIS-2: update native progress bar
        Write-Progress -Id $ProgressId -Activity $PhaseLabel `
            -Status ("{0} / {1} concluídos  |  Decorrido: {2}" -f $done, $total, $elapsedStr) `
            -PercentComplete $pct

        if ($done -lt $total) { Start-Sleep -Milliseconds 200 }
    }

    $sw.Stop()
    $totalTime = ("{0:D2}:{1:D2}:{2:D2}" -f [int]$sw.Elapsed.TotalHours, $sw.Elapsed.Minutes, $sw.Elapsed.Seconds)

    # Clear spinner line and close progress bar
    Write-Host ("`r" + (" " * 80) + "`r") -NoNewline
    Write-Progress -Id $ProgressId -Activity $PhaseLabel -Completed

    # Collect results
    $results = @()
    foreach ($job in $jobs) {
        $out = ""
        try {
            $raw = $job.PS.EndInvoke($job.Handle)
            if ($raw) { $out = $raw | Out-String }
            if ($job.PS.HadErrors) {
                $errs = $job.PS.Streams.Error | Out-String
                if ($errs.Trim()) { $out += ("`r`n--- ERRORS ---`r`n" + $errs) }
            }
        } catch {
            $out = ("ERROR: {0}" -f $_.Exception.Message)
        }
        $job.PS.Dispose()
        $results += [pscustomobject]@{ Label = $job.Label; Output = $out }
    }

    $pool.Close()
    $pool.Dispose()

    # Return results + total phase elapsed time
    return [pscustomobject]@{ Results = $results; Elapsed = $totalTime }
}

# ============================================================
# PERF-4: Per partner DC — ping + ports + showrepl in parallel
# One runspace per DC; ports use async BeginConnect in batch within the runspace
# ============================================================
function Test-PartnerDCParallel {
    param(
        [string[]]$PartnerList,
        [int[]]$Ports,
        [string]$RepadminPath,
        [int]$PortTimeoutMs = 2000,
        [int]$MaxRunspaces  = 8
    )

    $pool = [runspacefactory]::CreateRunspacePool(1, [Math]::Min($PartnerList.Count, $MaxRunspaces))
    $pool.ApartmentState = "MTA"
    $pool.Open()

    $dcScriptBlock = {
        param($PDC, $Ports, $RepadminExe, $TimeoutMs)
        $sb = New-Object System.Text.StringBuilder

        # Ping test
        try {
            $pingOk = Test-Connection -ComputerName $PDC -Count 2 -Quiet -ErrorAction SilentlyContinue
            [void]$sb.AppendLine(("Ping: {0}" -f $(if ($pingOk) { "OK" } else { "FAIL" })))
        } catch { [void]$sb.AppendLine("Ping: ERROR") }

        # TCP ports — fires all async connections at once, waits in batch
        $portJobs = @()
        foreach ($port in $Ports) {
            $client = New-Object System.Net.Sockets.TcpClient
            $portJobs += [pscustomobject]@{
                Port   = $port
                Client = $client
                AR     = $client.BeginConnect($PDC, $port, $null, $null)
            }
        }
        foreach ($pj in $portJobs) {
            $res = "ERROR"
            try {
                $ok = $pj.AR.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
                if ($ok) {
                    try { $pj.Client.EndConnect($pj.AR); $res = "OPEN" } catch { $res = "FAIL" }
                } else { $res = "TIMEOUT" }
            } catch { $res = "ERROR" }
            finally { try { $pj.Client.Close() } catch {} }
            [void]$sb.AppendLine(("TCP {0,5}: {1}" -f $pj.Port, $res))
        }

        # repadmin /showrepl (read-only)
        if ($RepadminExe -and (Get-Command $RepadminExe -ErrorAction SilentlyContinue)) {
            try {
                $replOut = & $RepadminExe /showrepl $PDC 2>&1 | Out-String
                [void]$sb.AppendLine("`r`nrepadmin /showrepl output:")
                [void]$sb.AppendLine($replOut)
            } catch {
                [void]$sb.AppendLine(("repadmin /showrepl failed: {0}" -f $_.Exception.Message))
            }
        }
        return $sb.ToString()
    }

    $jobs = @()
    foreach ($pdc in $PartnerList) {
        $ps = [powershell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript($dcScriptBlock).AddArgument($pdc).AddArgument($Ports).AddArgument($RepadminPath).AddArgument($PortTimeoutMs)
        $jobs += [pscustomobject]@{ DC = $pdc; PS = $ps; Handle = $ps.BeginInvoke() }
    }

    # VIS-3: per-DC progress — polling until all jobs complete
    $total      = $jobs.Count
    $done       = 0
    $spinFrames = @("|", "/", "-", "\")
    $spinIdx    = 0
    $sw         = [System.Diagnostics.Stopwatch]::StartNew()
    $dcStatus   = @{}   # DC -> partial status string for display

    Write-Progress -Id 10 -Activity "Testando DCs parceiros" `
        -Status ("0 / {0} DCs concluídos" -f $total) -PercentComplete 0

    $pendingJobs = [System.Collections.ArrayList]@($jobs)
    $results     = @()

    while ($pendingJobs.Count -gt 0) {
        $completed = @($pendingJobs | Where-Object { $_.Handle.IsCompleted })
        foreach ($job in $completed) {
            $out = ""
            try   { $out = $job.PS.EndInvoke($job.Handle) | Out-String }
            catch { $out = ("ERROR: {0}" -f $_.Exception.Message) }
            $job.PS.Dispose()
            $results += [pscustomobject]@{ DC = $job.DC; Output = $out }
            [void]$pendingJobs.Remove($job)
            $done++

            # VIS-3: extract ping result and open port count from output for inline display
            $pingStr  = if ($out -match "Ping: (OK|FAIL|ERROR)") { $Matches[1] } else { "?" }
            $openCnt  = ([regex]::Matches($out, "OPEN")).Count
            $replStr  = if ($out -match "repadmin /showrepl output:") { "Repl:OK" } else { "Repl:--" }
            $statusLine = ("  [DONE] [{0}/{1}] {2,-20}  Ping:{3,-5}  Ports:{4}/{5} open  {6}" -f `
                $done, $total, $job.DC, $pingStr, $openCnt, $PartnerList.Count, $replStr)
            Write-Host $statusLine -ForegroundColor $(if ($pingStr -eq "OK") { "Green" } else { "Yellow" })
        }

        if ($pendingJobs.Count -gt 0) {
            $elapsed    = $sw.Elapsed
            $elapsedStr = ("{0:D2}:{1:D2}:{2:D2}" -f [int]$elapsed.TotalHours, $elapsed.Minutes, $elapsed.Seconds)
            $frame      = $spinFrames[$spinIdx % $spinFrames.Count]
            $spinIdx++
            $pct        = [int](($done / $total) * 100)

            $spinLine = ("  {0}  Aguardando DCs parceiros...  [{1}/{2}]  {3}" -f `
                $frame, $done, $total, $elapsedStr)
            Write-Host ("`r" + $spinLine.PadRight(80)) -NoNewline -ForegroundColor DarkCyan

            Write-Progress -Id 10 -Activity "Testando DCs parceiros" `
                -Status ("{0} / {1} DCs concluídos  |  {2}" -f $done, $total, $elapsedStr) `
                -PercentComplete $pct

            Start-Sleep -Milliseconds 250
        }
    }

    $sw.Stop()
    Write-Host ("`r" + (" " * 80) + "`r") -NoNewline
    Write-Progress -Id 10 -Activity "Testando DCs parceiros" -Completed

    $pool.Close()
    $pool.Dispose()
    return $results
}

# ============================================================
# Write-Log — real-time execution log
# Writes to the log file AND the console simultaneously.
# Thread-safe via [System.IO.StreamWriter] with AutoFlush = true.
# ============================================================
$Global:LogWriter   = $null
$Script:PhaseTiming = [System.Collections.Specialized.OrderedDictionary]::new()
$Script:PhaseTimer  = $null

# VIS-4 helpers: marks start/end of each phase for the final summary
function Start-PhaseTimer([string]$Phase) {
    $Script:PhaseTimer = [System.Diagnostics.Stopwatch]::StartNew()
    $Script:PhaseTiming[$Phase] = @{ Status = "RUNNING"; Elapsed = ""; StartAt = (Get-Date) }
}

function Stop-PhaseTimer([string]$Phase, [string]$Status = "OK") {
    if ($Script:PhaseTimer) { $Script:PhaseTimer.Stop() }
    $elapsed = if ($Script:PhaseTimer) {
        ("{0:D2}:{1:D2}:{2:D2}" -f [int]$Script:PhaseTimer.Elapsed.TotalHours,
            $Script:PhaseTimer.Elapsed.Minutes, $Script:PhaseTimer.Elapsed.Seconds)
    } else { "--:--:--" }
    if ($Script:PhaseTiming.Contains($Phase)) {
        $Script:PhaseTiming[$Phase].Status  = $Status
        $Script:PhaseTiming[$Phase].Elapsed = $elapsed
    }
    $Script:PhaseTimer = $null
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO","WARN","ERROR","OK","START","END")]
        [string]$Level = "INFO"
    )
    $ts  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = ("[{0}] [{1,-5}] {2}" -f $ts, $Level, $Message)

    # Write to log file (always)
    if ($Global:LogWriter) {
        $Global:LogWriter.WriteLine($line)
        $Global:LogWriter.Flush()
    }

    # Write to console with color per level
    $color = switch ($Level) {
        "ERROR" { "Red"     }
        "WARN"  { "Yellow"  }
        "OK"    { "Green"   }
        "START" { "Cyan"    }
        "END"   { "Cyan"    }
        default { "Gray"    }
    }
    Write-Host $line -ForegroundColor $color
}

# ============================================================
# Setup — paths, file names, StreamWriters
# ============================================================
$ts             = Get-Date -Format "yyyyMMdd_HHmmss"
$dc             = $env:COMPUTERNAME
$domainDetected = Try-GetDomain -DomainParam $Domain
$ncDomain       = DomainToNC $domainDetected

# Base name shared by output report and log file
$baseName = "DC_Troubleshoot_{0}_{1}" -f $dc, $ts

# Directories
New-DirIfMissing $OutputDir
New-DirIfMissing $LogDir

# Final paths
$reportFile = Join-Path $OutputDir ("{0}.txt" -f $baseName)
$logFile    = Join-Path $LogDir    ("{0}.log" -f $baseName)

# Open log StreamWriter (AutoFlush = true → real-time)
$Global:LogWriter = New-Object System.IO.StreamWriter(
    $logFile,
    $false,
    (New-Object System.Text.UTF8Encoding($false))
)
$Global:LogWriter.AutoFlush = $true

# Open report StreamWriter (AutoFlush = false → manual flush = faster)
$writer = New-ReportWriter -Path $reportFile

Write-Log "Script iniciado" -Level START
$Script:GlobalSW = [System.Diagnostics.Stopwatch]::StartNew()
Write-Log ("DC           : {0}" -f $dc)
Write-Log ("Domain       : {0}" -f $domainDetected)
Write-Log ("Output file  : {0}" -f $reportFile)
Write-Log ("Log file     : {0}" -f $logFile)

Write-Text  $writer "DC Troubleshooting Report"
Write-Text  $writer ("DC           : {0}" -f $dc)
Write-Text  $writer ("Domain       : {0}" -f $domainDetected)
Write-Text  $writer ("Generated    : {0}" -f (Get-Date))
Write-Text  $writer ("Output file  : {0}" -f $reportFile)
Write-Text  $writer ("Log file     : {0}" -f $logFile)
$writer.Flush()

# ============================================================
# System info + Network (fast — sequential)
# ============================================================
Start-PhaseTimer "Sistema / Rede / Serviços"
Write-Log "Coletando informações do sistema" -Level INFO
Write-Section $writer "System / OS"
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $cs = Get-CimInstance Win32_ComputerSystem  -ErrorAction Stop
    Write-Text $writer ("OS: {0} (Build {1})"         -f $os.Caption, $os.BuildNumber)
    Write-Text $writer ("Version: {0}"                 -f $os.Version)
    Write-Text $writer ("LastBootUpTime: {0}"          -f $os.LastBootUpTime)
    Write-Text $writer ("Manufacturer/Model: {0} {1}" -f $cs.Manufacturer, $cs.Model)
} catch {
    Write-Text $writer ("ERROR collecting system info: {0}" -f $_.Exception.Message)
}

Write-Log "Coletando configuração de rede" -Level INFO
Write-Section $writer "Network Configuration"
Write-Text  $writer "IPv4 Addresses:"
Write-Block $writer (Get-LocalIPs   | Format-Table -AutoSize | Out-String)
Write-Text  $writer "`r`nDNS Client Server Addresses:"
Write-Block $writer (Get-DnsServers | Format-Table -AutoSize | Out-String)

Write-Log "Coletando status dos serviços críticos" -Level INFO
Write-Section $writer "Critical Services Status"
try {
    $svcNames = @("NTDS","DNS","Netlogon","KDC","W32Time","DFSR","LanmanServer","LanmanWorkstation","RpcSs")
    Write-Block $writer (Get-Service -Name $svcNames -ErrorAction SilentlyContinue |
        Select-Object Name, DisplayName, Status, StartType | Sort-Object Name |
        Format-Table -AutoSize | Out-String)
} catch {
    Write-Text $writer ("ERROR collecting services: {0}" -f $_.Exception.Message)
}
Stop-PhaseTimer "Sistema / Rede / Serviços" "OK"

# ============================================================
# PERF-2: Heavy external commands — all in parallel
# dcdiag full + dns, repadmin (4 sub-cmds), w32tm (3), dfsrdiag (3)
# Total time = duration of the slowest command (typically dcdiag /c /v /e)
# ============================================================
Start-PhaseTimer "Comandos Externos (dcdiag/repadmin/w32tm/dfsrdiag)"
Write-Log "Disparando comandos externos em paralelo (dcdiag / repadmin / w32tm / dfsrdiag)" -Level START
Write-Section $writer "--- PARALLEL PHASE: external commands (dcdiag / repadmin / w32tm / dfsrdiag) ---"
Write-Text $writer "Dispatching parallel runspaces — collecting results..."
$writer.Flush()

$dcdiagFullFile = Join-Path $OutputDir "dcdiag_full.txt"
$dcdiagDnsFile  = Join-Path $OutputDir "dcdiag_dns.txt"

# Uses [scriptblock]::Create with here-string to embed file paths inside runspaces
$sbDcdiagFull = [scriptblock]::Create(@"
    if (Get-Command dcdiag.exe -ErrorAction SilentlyContinue) {
        `$raw = & dcdiag.exe /c /v /e 2>&1
        `$out = `$raw | Out-String
        `$out | Out-File -FilePath '$dcdiagFullFile' -Encoding UTF8 -Force
        return `$out
    }
    return "dcdiag.exe not found."
"@)

$sbDcdiagDns = [scriptblock]::Create(@"
    if (Get-Command dcdiag.exe -ErrorAction SilentlyContinue) {
        `$raw = & dcdiag.exe /test:DNS /v 2>&1
        `$out = `$raw | Out-String
        `$out | Out-File -FilePath '$dcdiagDnsFile' -Encoding UTF8 -Force
        return `$out
    }
    return "dcdiag.exe not found."
"@)

$parallelTasks = @(
    [pscustomobject]@{ Label = "DCDIAG (full)";                                    ScriptBlock = $sbDcdiagFull }
    [pscustomobject]@{ Label = "DCDIAG - DNS tests";                               ScriptBlock = $sbDcdiagDns }
    [pscustomobject]@{ Label = "repadmin /replsummary";                            ScriptBlock = { if (Get-Command repadmin.exe -EA SilentlyContinue) { & repadmin.exe /replsummary 2>&1 | Out-String } else { "repadmin.exe not found." } } }
    [pscustomobject]@{ Label = "repadmin /showrepl * /verbose /all /intersite";    ScriptBlock = { if (Get-Command repadmin.exe -EA SilentlyContinue) { & repadmin.exe /showrepl * /verbose /all /intersite 2>&1 | Out-String } else { "repadmin.exe not found." } } }
    [pscustomobject]@{ Label = "repadmin /queue";                                  ScriptBlock = { if (Get-Command repadmin.exe -EA SilentlyContinue) { & repadmin.exe /queue 2>&1 | Out-String } else { "repadmin.exe not found." } } }
    [pscustomobject]@{ Label = "repadmin /showbackup *";                           ScriptBlock = { if (Get-Command repadmin.exe -EA SilentlyContinue) { & repadmin.exe /showbackup * 2>&1 | Out-String } else { "repadmin.exe not found." } } }
    [pscustomobject]@{ Label = "w32tm /query /status";                             ScriptBlock = { if (Get-Command w32tm.exe -EA SilentlyContinue) { & w32tm.exe /query /status 2>&1 | Out-String } else { "w32tm.exe not found." } } }
    [pscustomobject]@{ Label = "w32tm /query /configuration";                      ScriptBlock = { if (Get-Command w32tm.exe -EA SilentlyContinue) { & w32tm.exe /query /configuration 2>&1 | Out-String } else { "w32tm.exe not found." } } }
    [pscustomobject]@{ Label = "w32tm /query /peers";                              ScriptBlock = { if (Get-Command w32tm.exe -EA SilentlyContinue) { & w32tm.exe /query /peers 2>&1 | Out-String } else { "w32tm.exe not found." } } }
    [pscustomobject]@{ Label = "dfsrdiag replicationstate";                        ScriptBlock = { if (Get-Command dfsrdiag.exe -EA SilentlyContinue) { & dfsrdiag.exe replicationstate 2>&1 | Out-String } else { "dfsrdiag.exe not found." } } }
    [pscustomobject]@{ Label = "dfsrdiag pollad";                                  ScriptBlock = { if (Get-Command dfsrdiag.exe -EA SilentlyContinue) { & dfsrdiag.exe pollad 2>&1 | Out-String } else { "dfsrdiag.exe not found." } } }
    [pscustomobject]@{ Label = "dfsrdiag diag /test:ad /rgname:Domain System Volume"; ScriptBlock = { if (Get-Command dfsrdiag.exe -EA SilentlyContinue) { & dfsrdiag.exe diag /test:ad "/rgname:Domain System Volume" 2>&1 | Out-String } else { "dfsrdiag.exe not found." } } }
)

$parallelPhase = Invoke-ParallelTasks -Tasks $parallelTasks -MaxRunspaces 12 `
    -PhaseLabel "Comandos externos (dcdiag/repadmin/w32tm/dfsrdiag)" -ProgressId 1
Write-Log ("Fase de comandos externos concluída em {0}" -f $parallelPhase.Elapsed) -Level OK

foreach ($r in $parallelPhase.Results) {
    Write-Section $writer $r.Label
    Write-Block   $writer $r.Output
}
if (Test-Path $dcdiagFullFile) { Write-Text $writer ("Saved copy: {0}" -f $dcdiagFullFile) }
if (Test-Path $dcdiagDnsFile)  { Write-Text $writer ("Saved copy: {0}" -f $dcdiagDnsFile) }
Stop-PhaseTimer "Comandos Externos (dcdiag/repadmin/w32tm/dfsrdiag)" "OK"
Write-Log "Comandos externos concluídos" -Level OK

# ============================================================
# SYSVOL / NETLOGON (fast — sequential)
# ============================================================
Write-Log "Verificando shares SYSVOL/NETLOGON" -Level INFO
Write-Section $writer "SYSVOL / NETLOGON shares"
try {
    if (Command-Exists "Get-SmbShare") {
        Write-Block $writer (Get-SmbShare -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -in @("SYSVOL","NETLOGON") } |
            Select-Object Name, Path, Description | Format-Table -AutoSize | Out-String)
    } else {
        Write-Block $writer (net share 2>&1 | Out-String)
    }
} catch { Write-Text $writer ("ERROR checking shares: {0}" -f $_.Exception.Message) }

# ============================================================
# DNS SRV checks (fast — sequential)
# ============================================================
Write-Log "Verificando SRV records DNS" -Level INFO
Write-Section $writer "DNS - SRV records checks (local resolver)"
if ($domainDetected) {
    foreach ($q in @(
        "_ldap._tcp.dc._msdcs.$domainDetected",
        "_kerberos._tcp.dc._msdcs.$domainDetected",
        "_ldap._tcp.gc._msdcs.$domainDetected",
        "_ldap._tcp.$domainDetected"
    )) {
        try {
            Write-Text  $writer ("`r`nResolve-DnsName {0}:" -f $q)
            Write-Block $writer (Resolve-DnsName -Type SRV -Name $q -ErrorAction SilentlyContinue | Format-Table -AutoSize | Out-String)
        } catch { Write-Text $writer ("Resolve-DnsName failed for {0}: {1}" -f $q, $_.Exception.Message) }
    }
} else { Write-Text $writer "Domain could not be detected; skipping SRV checks." }

# ============================================================
# DC Discovery (fast — sequential)
# ============================================================
Write-Log "DC Discovery / Locator" -Level INFO
Write-Section $writer "DC Discovery / Locator"
if ($domainDetected -and (Command-Exists "nltest.exe")) {
    try {
        Write-Text  $writer "nltest /dsgetdc:"
        Write-Block $writer (nltest /dsgetdc:$domainDetected 2>&1 | Out-String)
        Write-Text  $writer "`r`nnltest /dclist:"
        Write-Block $writer (nltest /dclist:$domainDetected  2>&1 | Out-String)
    } catch { Write-Text $writer ("nltest failed: {0}" -f $_.Exception.Message) }
} else { Write-Text $writer "nltest.exe not found or domain not detected." }

# ============================================================
# PERF-4: Partner DCs — all tests in parallel
# ============================================================
Start-PhaseTimer "DCs Parceiros"
Write-Log "Iniciando testes de DCs parceiros em paralelo" -Level START
Write-Section $writer "Partner DCs: discovery + tests (parallel)"

if (-not $PartnerDCs -or $PartnerDCs.Count -eq 0) {
    if ($domainDetected -and (Command-Exists "nltest.exe")) {
        try {
            $found = @()
            foreach ($line in (nltest /dclist:$domainDetected 2>$null)) {
                if ($line -match "\\\\([A-Za-z0-9\-_\.]+)") { $found += $Matches[1] }
            }
            $PartnerDCs = $found | Sort-Object -Unique
        } catch { $PartnerDCs = @() }
    }
}

if ($PartnerDCs -and $PartnerDCs.Count -gt 0) {
    Write-Text $writer ("Partners (detected/provided): {0}" -f ($PartnerDCs -join ", "))
    $writer.Flush()

    $ports       = @(53, 88, 135, 389, 445, 464, 636, 3268, 3269, 5722, 9389)
    $repadminExe = if (Command-Exists "repadmin.exe") { "repadmin.exe" } else { "" }

    $dcResults = Test-PartnerDCParallel `
        -PartnerList   $PartnerDCs `
        -Ports         $ports `
        -RepadminPath  $repadminExe `
        -PortTimeoutMs 2000 `
        -MaxRunspaces  ([Math]::Min($PartnerDCs.Count, 10))

    foreach ($dcr in $dcResults) {
        Write-Section $writer ("Partner DC: {0}" -f $dcr.DC)
        Write-Block   $writer $dcr.Output

        if ((Command-Exists "nltest.exe") -and $domainDetected) {
            try {
                Write-Text  $writer ("nltest /sc_verify:{0}:" -f $domainDetected)
                Write-Block $writer (nltest /sc_verify:$domainDetected 2>&1 | Out-String)
            } catch { Write-Text $writer ("nltest /sc_verify failed: {0}" -f $_.Exception.Message) }
        }
    }
} else { Write-Text $writer "No partner DCs provided or discovered." }
Stop-PhaseTimer "DCs Parceiros" "OK"
Write-Log "Testes de DCs parceiros concluídos" -Level OK

# ============================================================
# PERF-3: Event Logs — 4 logs in parallel
# Total time = duration of the slowest log scan
# ============================================================
Start-PhaseTimer "Event Logs"
Write-Log "Disparando coleta de eventos em paralelo (4 logs)" -Level START
Write-Section $writer "--- PARALLEL PHASE: Event Logs (last 48h, Critical/Error/Warning) ---"
Write-Text $writer "Dispatching parallel runspaces for event collection..."
$writer.Flush()

$providerFilter = "RPC|Netlogon|Kerberos|Time|DFSR|DNS|LSA|Security-Kerberos"

$eventTasks = @(
    [pscustomobject]@{
        Label = "Event Logs (last 48h) - Directory Service"
        ScriptBlock = { $s=(Get-Date).AddHours(-48); try { Get-WinEvent -FilterHashtable @{LogName="Directory Service";StartTime=$s;Level=@(1,2,3)} -EA SilentlyContinue | Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message | Sort-Object TimeCreated -Descending | Select-Object -First 200 | Format-List | Out-String } catch { "ERROR: "+$_.Exception.Message } }
    }
    [pscustomobject]@{
        Label = "Event Logs (last 48h) - DNS Server"
        ScriptBlock = { $s=(Get-Date).AddHours(-48); try { Get-WinEvent -FilterHashtable @{LogName="DNS Server";StartTime=$s;Level=@(1,2,3)} -EA SilentlyContinue | Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message | Sort-Object TimeCreated -Descending | Select-Object -First 200 | Format-List | Out-String } catch { "ERROR: "+$_.Exception.Message } }
    }
    [pscustomobject]@{
        Label = "Event Logs (last 48h) - DFS Replication"
        ScriptBlock = { $s=(Get-Date).AddHours(-48); try { Get-WinEvent -FilterHashtable @{LogName="DFS Replication";StartTime=$s;Level=@(1,2,3)} -EA SilentlyContinue | Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message | Sort-Object TimeCreated -Descending | Select-Object -First 250 | Format-List | Out-String } catch { "ERROR: "+$_.Exception.Message } }
    }
    [pscustomobject]@{
        Label = "Event Logs (last 48h) - System (filtered providers)"
        ScriptBlock = [scriptblock]::Create(@"
            `$pf = '$providerFilter'
            `$s  = (Get-Date).AddHours(-48)
            try {
                Get-WinEvent -FilterHashtable @{LogName='System';StartTime=`$s;Level=@(1,2,3)} -EA SilentlyContinue |
                    Where-Object { `$_.ProviderName -match `$pf } |
                    Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message |
                    Sort-Object TimeCreated -Descending | Select-Object -First 250 | Format-List | Out-String
            } catch { "ERROR: "+`$_.Exception.Message }
"@)
    }
)

$eventPhase = Invoke-ParallelTasks -Tasks $eventTasks -MaxRunspaces 4 `
    -PhaseLabel "Event Logs (Directory Service / DNS / DFS / System)" -ProgressId 2
Write-Log ("Fase de eventos concluída em {0}" -f $eventPhase.Elapsed) -Level OK

foreach ($r in $eventPhase.Results) {
    Write-Section $writer $r.Label
    Write-Block   $writer $r.Output
}
Stop-PhaseTimer "Event Logs" "OK"
Write-Log "Coleta de eventos concluída" -Level OK

# ============================================================
# Firewall snapshot (fast — sequential)
# ============================================================
Start-PhaseTimer "Firewall"
Write-Log "Coletando snapshot do Firewall" -Level INFO
Write-Section $writer "Firewall Snapshot"
if (Command-Exists "Get-NetFirewallProfile") {
    try {
        Write-Block $writer (Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction | Format-Table -AutoSize | Out-String)
    } catch { Write-Text $writer ("Firewall snapshot failed: {0}" -f $_.Exception.Message) }
} else { Write-Text $writer "NetFirewall cmdlets not available." }
Stop-PhaseTimer "Firewall" "OK"


# ============================================================
# PERF-5: NEW sections (1-8) — all dispatched in one parallel pool
# Each task receives all required variables as arguments via AddArgument.
# Total time = duration of the slowest task (typically ntdsutil or Get-GPO).
# ============================================================
Start-PhaseTimer "AD/Kerberos/DNS/Repl/GPO/Security/OS/Sites (parallel)"
Write-Log "Disparando fase paralela: AD+Kerberos+DNS+Replicação+GPO+Segurança+SO+Sites" -Level START
Write-Section $writer "--- PARALLEL PHASE: AD Database / Kerberos / DNS / Replication / GPO / Security / OS / Sites ---"
Write-Text $writer "Dispatching parallel runspaces — collecting results..."
$writer.Flush()

# ── Helper: build a here-string scriptblock with injected variables ──────────
# PS 5.1 runspaces do not inherit the parent scope; every variable needed
# inside a runspace must be embedded via [scriptblock]::Create() + here-string
# OR passed as AddArgument and received via param().
# We use the AddArgument pattern: each scriptblock starts with a param() block.

# ── Build the task list using [scriptblock]::Create with here-strings ────────
# Each scriptblock has the required runtime values ($domainDetected, $ncDomain)
# baked in via PowerShell string expansion before [scriptblock]::Create() is called.
# This is the same pattern used for $sbDcdiagFull/$sbDcdiagDns above (PERF-2).

$newPhaseTasks = @(

    # NEW-1: AD Database & FSMO
    [pscustomobject]@{
        Label = "AD Database & FSMO"
        ScriptBlock = [scriptblock]::Create(@"
            `$sb = New-Object System.Text.StringBuilder
            if (Get-Command netdom.exe -ErrorAction SilentlyContinue) {
                try {
                    [void]`$sb.AppendLine('--- netdom query fsmo ---')
                    [void]`$sb.AppendLine(( & netdom.exe query fsmo 2>&1 | Out-String ))
                } catch { [void]`$sb.AppendLine("netdom query fsmo failed: `$_") }
            } else { [void]`$sb.AppendLine('netdom.exe not found; skipping FSMO query.') }

            if ('$domainDetected' -and (Get-Command nltest.exe -ErrorAction SilentlyContinue)) {
                try {
                    [void]`$sb.AppendLine("`r`n--- nltest /sc_query (PDC Emulator channel) ---")
                    [void]`$sb.AppendLine(( & nltest.exe /sc_query:'$domainDetected' 2>&1 | Out-String ))
                } catch { [void]`$sb.AppendLine("nltest /sc_query failed: `$_") }
            }

            if (Get-Command ntdsutil.exe -ErrorAction SilentlyContinue) {
                try {
                    [void]`$sb.AppendLine("`r`n--- ntdsutil: files integrity ---")
                    [void]`$sb.AppendLine(( & ntdsutil.exe 'files' 'integrity' 'quit' 'quit' 2>&1 | Out-String ))
                } catch { [void]`$sb.AppendLine("ntdsutil integrity check failed: `$_") }
            } else { [void]`$sb.AppendLine('ntdsutil.exe not found; skipping integrity check.') }

            try {
                `$ntdsPath = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' ``
                    -Name 'DSA Database file' -ErrorAction SilentlyContinue).'DSA Database file'
                if (`$ntdsPath -and (Test-Path `$ntdsPath)) {
                    `$f = Get-Item `$ntdsPath -ErrorAction SilentlyContinue
                    [void]`$sb.AppendLine(("NTDS.dit path      : {0}" -f `$ntdsPath))
                    [void]`$sb.AppendLine(("NTDS.dit size (MB) : {0:N1}" -f (`$f.Length / 1MB)))
                    [void]`$sb.AppendLine(("NTDS.dit last write: {0}"    -f `$f.LastWriteTime))
                }
            } catch { [void]`$sb.AppendLine("ERROR reading NTDS.dit info: `$_") }
            return `$sb.ToString()
"@)
    }

    # NEW-2: Kerberos & Authentication
    [pscustomobject]@{
        Label = "Kerberos & Authentication"
        ScriptBlock = [scriptblock]::Create(@"
            `$sb = New-Object System.Text.StringBuilder
            if (Get-Command klist.exe -ErrorAction SilentlyContinue) {
                try {
                    [void]`$sb.AppendLine('--- klist tickets ---')
                    [void]`$sb.AppendLine(( & klist.exe tickets 2>&1 | Out-String ))
                    [void]`$sb.AppendLine("`r`n--- klist tgt ---")
                    [void]`$sb.AppendLine(( & klist.exe tgt 2>&1 | Out-String ))
                } catch { [void]`$sb.AppendLine("klist failed: `$_") }
            } else { [void]`$sb.AppendLine('klist.exe not found.') }

            if (Get-Command nltest.exe -ErrorAction SilentlyContinue) {
                try {
                    [void]`$sb.AppendLine("`r`n--- nltest /domain_trusts ---")
                    [void]`$sb.AppendLine(( & nltest.exe /domain_trusts 2>&1 | Out-String ))
                } catch { [void]`$sb.AppendLine("nltest /domain_trusts failed: `$_") }
            }

            [void]`$sb.AppendLine("`r`n--- Account Lockout Events (4740, last 48h) ---")
            try {
                `$evts = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4740;StartTime=(Get-Date).AddHours(-48)} ``
                    -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,Message |
                    Sort-Object TimeCreated -Descending | Select-Object -First 100
                if (`$evts) { [void]`$sb.AppendLine(( `$evts | Format-List | Out-String )) }
                else        { [void]`$sb.AppendLine('No account lockout events (4740) found in the last 48h.') }
            } catch { [void]`$sb.AppendLine("ERROR reading lockout events: `$_") }

            [void]`$sb.AppendLine("`r`n--- Kerberos Operational Events (last 48h) ---")
            try {
                `$kevts = Get-WinEvent -FilterHashtable @{
                    LogName='Microsoft-Windows-Security-Kerberos/Operational'
                    StartTime=(Get-Date).AddHours(-48)
                } -ErrorAction SilentlyContinue |
                    Select-Object TimeCreated,Id,LevelDisplayName,Message |
                    Sort-Object TimeCreated -Descending | Select-Object -First 100
                if (`$kevts) { [void]`$sb.AppendLine(( `$kevts | Format-List | Out-String )) }
                else         { [void]`$sb.AppendLine('No Kerberos operational events found.') }
            } catch { [void]`$sb.AppendLine('Kerberos Operational log not available or empty.') }
            return `$sb.ToString()
"@)
    }

    # NEW-3: DNS Deep-Dive
    [pscustomobject]@{
        Label = "DNS Deep-Dive"
        ScriptBlock = [scriptblock]::Create(@"
            `$sb = New-Object System.Text.StringBuilder
            if (Get-Command dnscmd.exe -ErrorAction SilentlyContinue) {
                try { [void]`$sb.AppendLine('--- dnscmd /enumzones ---'); [void]`$sb.AppendLine(( & dnscmd.exe /enumzones 2>&1 | Out-String )) } catch { [void]`$sb.AppendLine("dnscmd /enumzones failed: `$_") }
                try { [void]`$sb.AppendLine("`r`n--- dnscmd /statistics ---"); [void]`$sb.AppendLine(( & dnscmd.exe /statistics 2>&1 | Out-String )) } catch { [void]`$sb.AppendLine("dnscmd /statistics failed: `$_") }
            } else { [void]`$sb.AppendLine('dnscmd.exe not found; skipping zone and statistics checks.') }

            [void]`$sb.AppendLine("`r`n--- _msdcs SRV records ---")
            foreach (`$q in @('_ldap._tcp.pdc._msdcs.$domainDetected','_ldap._tcp.gc._msdcs.$domainDetected','_kerberos._tcp.dc._msdcs.$domainDetected','_ldap._tcp.dc._msdcs.$domainDetected')) {
                try { [void]`$sb.AppendLine(("Resolve-DnsName (SRV) {0}:" -f `$q)); [void]`$sb.AppendLine(( Resolve-DnsName -Type SRV -Name `$q -EA SilentlyContinue | Format-Table -AutoSize | Out-String )) }
                catch { [void]`$sb.AppendLine(("Resolve-DnsName failed for {0}: {1}" -f `$q, `$_)) }
            }

            [void]`$sb.AppendLine("`r`n--- Reverse PTR lookup for DC IPs ---")
            `$ips = Get-NetIPAddress -AddressFamily IPv4 -EA SilentlyContinue | Where-Object { `$_.IPAddress -and `$_.IPAddress -notlike '169.254*' }
            foreach (`$ip in `$ips) {
                try {
                    `$ptr = Resolve-DnsName -Name `$ip.IPAddress -Type PTR -EA SilentlyContinue
                    `$s   = if (`$ptr) { (`$ptr | Select-Object -ExpandProperty NameHost) -join ', ' } else { 'NO PTR RECORD' }
                    [void]`$sb.AppendLine(("{0,-20} -> {1}" -f `$ip.IPAddress, `$s))
                } catch { [void]`$sb.AppendLine(("{0,-20} -> ERROR: {1}" -f `$ip.IPAddress, `$_)) }
            }
            return `$sb.ToString()
"@)
    }

    # NEW-4: Advanced AD Replication
    [pscustomobject]@{
        Label = "Advanced AD Replication"
        ScriptBlock = [scriptblock]::Create(@"
            `$sb = New-Object System.Text.StringBuilder
            if (Get-Command repadmin.exe -ErrorAction SilentlyContinue) {
                try { [void]`$sb.AppendLine('--- repadmin /istg ---');         [void]`$sb.AppendLine(( & repadmin.exe /istg 2>&1 | Out-String )) }         catch { [void]`$sb.AppendLine("repadmin /istg failed: `$_") }
                try { [void]`$sb.AppendLine("`r`n--- repadmin /bridgeheads ---"); [void]`$sb.AppendLine(( & repadmin.exe /bridgeheads 2>&1 | Out-String )) } catch { [void]`$sb.AppendLine("repadmin /bridgeheads failed: `$_") }
                try { [void]`$sb.AppendLine("`r`n--- repadmin /showism ---");     [void]`$sb.AppendLine(( & repadmin.exe /showism 2>&1 | Out-String )) }     catch { [void]`$sb.AppendLine("repadmin /showism failed: `$_") }
                try { [void]`$sb.AppendLine("`r`n--- repadmin /showutdvec * /nocache ---"); [void]`$sb.AppendLine(( & repadmin.exe /showutdvec * /nocache 2>&1 | Out-String )) } catch { [void]`$sb.AppendLine("repadmin /showutdvec failed: `$_") }

                try {
                    [void]`$sb.AppendLine("`r`n--- Tombstone lifetime vs replication lag ---")
                    `$tsl = 60
                    if ('$ncDomain') {
                        `$tslRaw = Get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$ncDomain" ``
                            -Properties tombstoneLifetime -ErrorAction SilentlyContinue
                        if (`$tslRaw -and `$tslRaw.tombstoneLifetime) { `$tsl = `$tslRaw.tombstoneLifetime }
                    }
                    [void]`$sb.AppendLine(("Tombstone lifetime (days): {0}" -f `$tsl))
                    `$replSum = & repadmin.exe /replsummary 2>&1 | Out-String
                    `$maxLag = 0
                    foreach (`$line in (`$replSum -split "\`n")) {
                        if (`$line -match 'largest delta\s*:\s*(\d+)d') { `$d=[int]`$Matches[1]; if(`$d -gt `$maxLag){`$maxLag=`$d} }
                    }
                    [void]`$sb.AppendLine(("Largest replication delta (days): {0}" -f `$maxLag))
                    if (`$maxLag -gt (`$tsl * 0.8)) { [void]`$sb.AppendLine('WARNING: Replication lag exceeds 80% of tombstone lifetime -- USN rollback risk!') }
                    else { [void]`$sb.AppendLine('Replication lag is within safe tombstone lifetime threshold.') }
                } catch { [void]`$sb.AppendLine("ERROR checking tombstone lag: `$_") }
            } else { [void]`$sb.AppendLine('repadmin.exe not found.') }
            return `$sb.ToString()
"@)
    }

    # NEW-5: GPO & SYSVOL Consistency
    [pscustomobject]@{
        Label = "GPO & SYSVOL Consistency"
        ScriptBlock = [scriptblock]::Create(@"
            `$sb = New-Object System.Text.StringBuilder
            if (-not '$domainDetected') { [void]`$sb.AppendLine('Domain not detected; skipping GPO checks.'); return `$sb.ToString() }

            `$adGpos = `$null; `$adGpoCount = 0
            try {
                if (Get-Command Get-GPO -ErrorAction SilentlyContinue) {
                    `$adGpos     = Get-GPO -All -ErrorAction SilentlyContinue
                    `$adGpoCount = if (`$adGpos) { @(`$adGpos).Count } else { 0 }
                    [void]`$sb.AppendLine(("GPOs in AD: {0}" -f `$adGpoCount))
                    [void]`$sb.AppendLine(( `$adGpos | Select-Object DisplayName,Id,GpoStatus,CreationTime,ModificationTime | Sort-Object DisplayName | Format-Table -AutoSize | Out-String ))
                } else { [void]`$sb.AppendLine('Get-GPO not available (GroupPolicy module not loaded).') }
            } catch { [void]`$sb.AppendLine("ERROR listing AD GPOs: `$_") }

            `$sysvolPath = '\\$domainDetected\SYSVOL\$domainDetected\Policies'
            try {
                if (Test-Path `$sysvolPath) {
                    `$svGpos  = Get-ChildItem `$sysvolPath -Directory -EA SilentlyContinue | Where-Object { `$_.Name -match '^\{[0-9A-Fa-f\-]{36}\}$' }
                    `$svCount = if (`$svGpos) { @(`$svGpos).Count } else { 0 }
                    [void]`$sb.AppendLine(("GPO folders in SYSVOL: {0}" -f `$svCount))
                    if (`$adGpos -and `$adGpoCount -gt 0 -and `$svCount -gt 0) {
                        `$adIds = @(`$adGpos | ForEach-Object { "{`$(`$_.Id)}" })
                        `$svIds = @(`$svGpos | Select-Object -ExpandProperty Name)
                        `$missing  = `$adIds | Where-Object { `$_ -notin `$svIds }
                        `$orphaned = `$svIds | Where-Object { `$_ -notin `$adIds }
                        if (`$missing)  { [void]`$sb.AppendLine('WARNING -- GPOs in AD but missing from SYSVOL:');        `$missing  | ForEach-Object { [void]`$sb.AppendLine("  `$_") } } else { [void]`$sb.AppendLine('No GPOs missing from SYSVOL.') }
                        if (`$orphaned) { [void]`$sb.AppendLine('WARNING -- GPO folders in SYSVOL but not in AD:');       `$orphaned | ForEach-Object { [void]`$sb.AppendLine("  `$_") } } else { [void]`$sb.AppendLine('No orphaned GPO folders in SYSVOL.') }
                    }
                } else { [void]`$sb.AppendLine(("SYSVOL GPO path not accessible: {0}" -f `$sysvolPath)) }
            } catch { [void]`$sb.AppendLine("ERROR checking SYSVOL GPO folders: `$_") }

            if (Get-Command gpresult.exe -ErrorAction SilentlyContinue) {
                try { [void]`$sb.AppendLine("`r`n--- gpresult /r (DC computer policy) ---"); [void]`$sb.AppendLine(( & gpresult.exe /r /scope:computer 2>&1 | Out-String )) }
                catch { [void]`$sb.AppendLine("gpresult failed: `$_") }
            }
            return `$sb.ToString()
"@)
    }

    # NEW-6: Security & Audit (no domain variables needed)
    [pscustomobject]@{
        Label = "Security & Audit"
        ScriptBlock = {
            $sb = New-Object System.Text.StringBuilder
            foreach ($grp in @("Domain Admins","Enterprise Admins","Schema Admins","Administrators")) {
                try {
                    [void]$sb.AppendLine(("`r`nGroup: {0}" -f $grp))
                    [void]$sb.AppendLine(( & net.exe group $grp /domain 2>&1 | Out-String ))
                } catch { [void]$sb.AppendLine(("ERROR querying group '{0}': {1}" -f $grp, $_)) }
            }
            if (Get-Command auditpol.exe -ErrorAction SilentlyContinue) {
                try { [void]$sb.AppendLine("`r`n--- auditpol /get /category:* ---"); [void]$sb.AppendLine(( & auditpol.exe /get /category:* 2>&1 | Out-String )) }
                catch { [void]$sb.AppendLine("auditpol failed: $_") }
            } else { [void]$sb.AppendLine("auditpol.exe not found.") }
            $ids = @(4625,4648,4672,4719,4728,4732,4756,4964)
            [void]$sb.AppendLine(("`r`n--- Critical Security Events (IDs: {0}, last 48h) ---" -f ($ids -join ",")))
            try {
                $evts = Get-WinEvent -FilterHashtable @{LogName="Security";Id=$ids;StartTime=(Get-Date).AddHours(-48)} -EA SilentlyContinue |
                    Select-Object TimeCreated,Id,LevelDisplayName,Message | Sort-Object TimeCreated -Descending | Select-Object -First 200
                if ($evts) { [void]$sb.AppendLine(( $evts | Format-List | Out-String )) }
                else       { [void]$sb.AppendLine("No critical Security events found in the last 48h.") }
            } catch { [void]$sb.AppendLine("ERROR reading Security events: $_") }
            return $sb.ToString()
        }
    }

    # NEW-7: OS Health (no domain variables needed)
    [pscustomobject]@{
        Label = "OS Health (Disk / Memory / Hotfixes)"
        ScriptBlock = {
            $sb = New-Object System.Text.StringBuilder
            [void]$sb.AppendLine("--- Disk Volumes ---")
            try {
                $vols = Get-Volume -EA SilentlyContinue | Where-Object { $_.DriveType -eq "Fixed" -and $_.DriveLetter } |
                    Select-Object DriveLetter,FileSystemLabel,
                        @{N="SizeGB"; E={[Math]::Round($_.Size/1GB,1)}},
                        @{N="FreeGB"; E={[Math]::Round($_.SizeRemaining/1GB,1)}},
                        @{N="FreePct";E={if($_.Size -gt 0){[Math]::Round(($_.SizeRemaining/$_.Size)*100,1)}else{0}}},
                        HealthStatus
                [void]$sb.AppendLine(( $vols | Format-Table -AutoSize | Out-String ))
                foreach ($v in $vols) {
                    if ($v.FreePct -lt 15) { [void]$sb.AppendLine(("WARNING: Drive {0}: only {1}% free ({2} GB) -- AD may fail if disk fills!" -f $v.DriveLetter,$v.FreePct,$v.FreeGB)) }
                }
            } catch { [void]$sb.AppendLine("ERROR querying volumes: $_") }

            [void]$sb.AppendLine("`r`n--- NTDS.dit and SYSVOL volume free space ---")
            try {
                $ntdsReg = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "DSA Database file" -EA SilentlyContinue)."DSA Database file"
                if ($ntdsReg) {
                    $drv = $ntdsReg.Substring(0,1)
                    $v   = Get-Volume -DriveLetter $drv -EA SilentlyContinue
                    if ($v) { [void]$sb.AppendLine(("NTDS.dit volume ({0}:) -- Free: {1:N1} GB  ({2:N1}%)" -f $drv,[Math]::Round($v.SizeRemaining/1GB,1),[Math]::Round(($v.SizeRemaining/$v.Size)*100,1))) }
                }
                $cv = Get-Volume -DriveLetter "C" -EA SilentlyContinue
                if ($cv) { [void]$sb.AppendLine(("SYSVOL volume (C:) -- Free: {0:N1} GB  ({1:N1}%)" -f [Math]::Round($cv.SizeRemaining/1GB,1),[Math]::Round(($cv.SizeRemaining/$cv.Size)*100,1))) }
            } catch { [void]$sb.AppendLine("ERROR checking NTDS/SYSVOL volume: $_") }

            [void]$sb.AppendLine("`r`n--- Memory: Non-Paged Pool ---")
            try {
                $np  = (Get-Counter "\Memory\Pool Nonpaged Bytes" -EA SilentlyContinue).CounterSamples[0].CookedValue
                $npg = [Math]::Round($np/1GB,2)
                [void]$sb.AppendLine(("Non-Paged Pool: {0} GB  ({1:N0} bytes)" -f $npg,$np))
                if ($npg -gt 2) { [void]$sb.AppendLine("WARNING: Non-paged pool > 2 GB -- potential LSASS memory pressure.") }
            } catch { [void]$sb.AppendLine("ERROR reading Non-Paged Pool counter.") }
            try {
                $o = Get-CimInstance Win32_OperatingSystem -EA SilentlyContinue
                if ($o) {
                    [void]$sb.AppendLine(("Total Physical Memory : {0:N1} GB" -f ($o.TotalVisibleMemorySize/1MB)))
                    [void]$sb.AppendLine(("Free Physical Memory  : {0:N1} GB" -f ($o.FreePhysicalMemory/1MB)))
                }
            } catch { [void]$sb.AppendLine("ERROR reading memory CIM data.") }

            [void]$sb.AppendLine("`r`n--- Installed Hotfixes ---")
            try {
                $hf = Get-HotFix -EA SilentlyContinue | Sort-Object InstalledOn -Descending
                [void]$sb.AppendLine(( $hf | Select-Object HotFixID,Description,InstalledOn | Format-Table -AutoSize | Out-String ))
                $rec = $hf | Where-Object { $_.InstalledOn -and $_.InstalledOn -gt (Get-Date).AddDays(-90) }
                if ($rec) { [void]$sb.AppendLine(("Hotfixes installed in the last 90 days: {0}" -f @($rec).Count)) }
            } catch { [void]$sb.AppendLine("ERROR reading hotfixes: $_") }
            return $sb.ToString()
        }
    }

    # NEW-8: AD Sites & Subnets
    [pscustomobject]@{
        Label = "AD Sites & Subnets"
        ScriptBlock = [scriptblock]::Create(@"
            `$sb = New-Object System.Text.StringBuilder
            if (Get-Command nltest.exe -ErrorAction SilentlyContinue) {
                try { [void]`$sb.AppendLine('--- nltest /dsgetsite ---'); [void]`$sb.AppendLine(( & nltest.exe /dsgetsite 2>&1 | Out-String )) }
                catch { [void]`$sb.AppendLine("nltest /dsgetsite failed: `$_") }
            }
            if (Get-Command repadmin.exe -ErrorAction SilentlyContinue) {
                try { [void]`$sb.AppendLine("`r`n--- repadmin /siteoptions ---"); [void]`$sb.AppendLine(( & repadmin.exe /siteoptions 2>&1 | Out-String )) }
                catch { [void]`$sb.AppendLine("repadmin /siteoptions failed: `$_") }
            }
            if (-not '$ncDomain') { [void]`$sb.AppendLine('Domain NC not available; skipping AD Sites query.'); return `$sb.ToString() }
            try {
                `$configNC = 'CN=Configuration,$ncDomain'
                [void]`$sb.AppendLine("`r`n--- AD Sites ---")
                [void]`$sb.AppendLine(( Get-ADObject -Filter { objectClass -eq 'site' } -SearchBase "CN=Sites,`$configNC" -Properties name -EA SilentlyContinue | Select-Object Name | Format-Table -AutoSize | Out-String ))
                [void]`$sb.AppendLine("`r`n--- AD Subnets ---")
                `$subnets = Get-ADObject -Filter { objectClass -eq 'subnet' } -SearchBase "CN=Subnets,CN=Sites,`$configNC" -Properties name,siteObject -EA SilentlyContinue | Select-Object Name,siteObject
                [void]`$sb.AppendLine(( `$subnets | Format-Table -AutoSize | Out-String ))
                [void]`$sb.AppendLine("`r`n--- DC IP to subnet mapping check ---")
                `$dcIPs = (Get-NetIPAddress -AddressFamily IPv4 -EA SilentlyContinue | Where-Object { `$_.IPAddress -and `$_.IPAddress -notlike '169.254*' }).IPAddress
                `$snList = @(`$subnets | Select-Object -ExpandProperty Name)
                foreach (`$ip in `$dcIPs) {
                    `$covered = `$false
                    foreach (`$sn in `$snList) {
                        try {
                            `$parts=`$sn -split '/'; `$prefix=[int]`$parts[1]
                            `$snAddr=[System.Net.IPAddress]::Parse(`$parts[0]); `$ipAddr=[System.Net.IPAddress]::Parse(`$ip)
                            `$mask=[System.Net.IPAddress]([uint32]([uint32]0xFFFFFFFF -shl (32-`$prefix)))
                            `$snNet=[System.Net.IPAddress]([byte[]]@((`$snAddr.GetAddressBytes()[0]-band`$mask.GetAddressBytes()[0]),(`$snAddr.GetAddressBytes()[1]-band`$mask.GetAddressBytes()[1]),(`$snAddr.GetAddressBytes()[2]-band`$mask.GetAddressBytes()[2]),(`$snAddr.GetAddressBytes()[3]-band`$mask.GetAddressBytes()[3])))
                            `$ipNet=[System.Net.IPAddress]([byte[]]@((`$ipAddr.GetAddressBytes()[0]-band`$mask.GetAddressBytes()[0]),(`$ipAddr.GetAddressBytes()[1]-band`$mask.GetAddressBytes()[1]),(`$ipAddr.GetAddressBytes()[2]-band`$mask.GetAddressBytes()[2]),(`$ipAddr.GetAddressBytes()[3]-band`$mask.GetAddressBytes()[3])))
                            if (`$snNet.ToString() -eq `$ipNet.ToString()) { `$covered=`$true; break }
                        } catch {}
                    }
                    [void]`$sb.AppendLine(("  {0,-20} -> {1}" -f `$ip, $(if(`$covered){'COVERED'}else{'WARNING: not mapped to any AD subnet'})))
                }
                [void]`$sb.AppendLine("`r`n--- Site Links ---")
                [void]`$sb.AppendLine(( Get-ADObject -Filter { objectClass -eq 'siteLink' } -SearchBase "CN=Sites,`$configNC" -Properties name,cost,replInterval -EA SilentlyContinue | Select-Object Name,cost,replInterval | Format-Table -AutoSize | Out-String ))
            } catch { [void]`$sb.AppendLine("ERROR reading Sites/Subnets from AD: `$_") }
            return `$sb.ToString()
"@)
    }
)

$newPhase = Invoke-ParallelTasks -Tasks $newPhaseTasks -MaxRunspaces 8 `
    -PhaseLabel "AD/Kerberos/DNS/Replicação/GPO/Segurança/SO/Sites" -ProgressId 3
Write-Log ("Fase paralela NEW concluída em {0}" -f $newPhase.Elapsed) -Level OK

# Write all results to report in order
$newPhaseLabels = @(
    "AD Database & FSMO",
    "Kerberos & Authentication",
    "DNS Deep-Dive",
    "Advanced AD Replication",
    "GPO & SYSVOL Consistency",
    "Security & Audit",
    "OS Health (Disk / Memory / Hotfixes)",
    "AD Sites & Subnets"
)
foreach ($lbl in $newPhaseLabels) {
    $r = $newPhase.Results | Where-Object { $_.Label -eq $lbl }
    if ($r) {
        Write-Section $writer $r.Label
        Write-Block   $writer $r.Output
    }
}

# Register all 8 phases in PhaseTiming for the final summary
$phaseElapsed = $newPhase.Elapsed
foreach ($lbl in $newPhaseLabels) {
    $Script:PhaseTiming[$lbl] = @{ Status = "OK"; Elapsed = $phaseElapsed; StartAt = (Get-Date) }
}
Stop-PhaseTimer "AD/Kerberos/DNS/Repl/GPO/Security/OS/Sites (parallel)" "OK"
Write-Log "Fase paralela NEW concluída" -Level OK


# ============================================================
# VIS-4: Final summary table in color on the console
# ============================================================
function Write-Summary {
    param([System.Collections.Specialized.OrderedDictionary]$Timing)

    $sep = ("─" * 70)
    Write-Host ""
    Write-Host $sep -ForegroundColor DarkGray
    Write-Host ("  {0,-44}  {1,-8}  {2}" -f "FASE", "STATUS", "DURAÇÃO") -ForegroundColor White
    Write-Host $sep -ForegroundColor DarkGray

    foreach ($phase in $Timing.Keys) {
        $entry   = $Timing[$phase]
        $status  = $entry.Status
        $elapsed = if ($entry.Elapsed) { $entry.Elapsed } else { "--:--:--" }

        $color = switch ($status) {
            "OK"      { "Green"  }
            "WARN"    { "Yellow" }
            "ERROR"   { "Red"    }
            "RUNNING" { "Cyan"   }
            default   { "Gray"   }
        }

        $icon = switch ($status) {
            "OK"    { "[OK]   " }
            "WARN"  { "[WARN] " }
            "ERROR" { "[ERROR]" }
            default { "[?]    " }
        }

        Write-Host ("  {0,-44}  " -f $phase) -NoNewline -ForegroundColor Gray
        Write-Host ("{0,-8}  " -f $icon)     -NoNewline -ForegroundColor $color
        Write-Host $elapsed                               -ForegroundColor DarkGray
    }

    Write-Host $sep -ForegroundColor DarkGray
    Write-Host ""
}

Write-Summary -Timing $Script:PhaseTiming

# ============================================================
# Done — close StreamWriters (report and log)
# ============================================================
Write-Section $writer "DONE"
# Write phase summary to the report file as well
Write-Text $writer "PHASE SUMMARY:"
foreach ($phase in $Script:PhaseTiming.Keys) {
    $e = $Script:PhaseTiming[$phase]
    Write-Text $writer ("  {0,-44}  {1,-8}  {2}" -f $phase, $e.Status, $e.Elapsed)
}
Write-Text $writer ""
Write-Text $writer ("Report file : {0}" -f $reportFile)
Write-Text $writer ("Log file    : {0}" -f $logFile)
$writer.Flush()
$writer.Close()
$writer.Dispose()

Write-Log ("Relatório salvo em : {0}" -f $reportFile) -Level OK
Write-Log ("Log salvo em       : {0}" -f $logFile)    -Level OK
$Script:GlobalSW.Stop()
$totalElapsed = ("{0:D2}:{1:D2}:{2:D2}" -f `
    [int]$Script:GlobalSW.Elapsed.TotalHours,
    $Script:GlobalSW.Elapsed.Minutes,
    $Script:GlobalSW.Elapsed.Seconds)

# Write total execution time to the report (before closing the writer)
Write-Text $writer ("Tempo total de execução : {0}" -f $totalElapsed)
$writer.Flush()

Write-Log ("Tempo total de execução : {0}" -f $totalElapsed) -Level END
Write-Log "Script concluído" -Level END

$Global:LogWriter.Close()
$Global:LogWriter.Dispose()
$Global:LogWriter = $null

Write-Host ""
Write-Host ("Output : {0}" -f $reportFile) -ForegroundColor Green
Write-Host ("Log    : {0}" -f $logFile)    -ForegroundColor Green
Write-Host ("Tempo  : {0}" -f $totalElapsed) -ForegroundColor Cyan
Write-Host ""
