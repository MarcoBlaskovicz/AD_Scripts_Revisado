#Requires -Version 7.1
<#
.SYNOPSIS
    Collects computer object information from one or more Active Directory domains
    and exports the results to CSV files.

.DESCRIPTION
    At startup, the script loads the ActiveDirectory module, queries the current AD
    forest, and presents an interactive menu that lets the operator choose the
    collection scope:

        [1] Entire forest    — all domains are collected automatically.
        [2] Single domain    — the operator picks one domain from a numbered list.
        [3] Multiple domains — the operator picks two or more domains by entering
                               their numbers separated by commas (e.g. 1,3).

    After scope selection a confirmation prompt is displayed. The operator must
    press Enter to start the collection or Ctrl+C to abort, preventing accidental
    runs.

    The following attributes are collected from every computer object in the
    selected scope:

        CN, DistinguishedName, ObjectClass, LastLogonDate, LastLogonTimestamp,
        pwdLastSet, userAccountControl, location, OperatingSystem, displayName

    Two additional fields are appended to each record:
        Domain      - FQDN of the source domain.
        CollectedAt - Timestamp of when the script run started.

    Output files (all stamped with the same yyyyMMdd_HHmmss run timestamp):

        Per-domain CSV  : C:\Temp\OutputScripts\Computers\COMPUTERS_<domain>_<stamp>.csv
        Forest CSV      : C:\Temp\OutputScripts\Computers\COMPUTERS_FOREST_<stamp>.csv
                          (only when scope = entire forest or multiple domains)
        General log     : C:\Temp\LogScripts\Computers\Computers_Forest_<stamp>.log
        Per-domain log  : C:\Temp\LogScripts\Computers\Computers_<domain>_<stamp>.log

    All output directories are created automatically if they do not exist.
    Logging and CSV writes are performed in real time via System.IO.StreamWriter
    with AutoFlush enabled — files remain readable even if the run is interrupted.

    At the end of the run a boxed summary is printed to the console showing elapsed
    time, domains processed (OK vs. errors), total records collected, and output
    paths. The summary box is green on a clean run and yellow if any domain failed.

.PARAMETER
    None. All configuration is handled through the interactive menu at runtime.

.OUTPUTS
    System.IO.FileInfo
        Per-domain CSV files, an optional forest-wide consolidated CSV, and log
        files as described above.

.EXAMPLE
    PS> .\Get-ADComputers_Forest.ps1

    Loads the AD module, discovers the forest, presents the scope menu, waits for
    confirmation, runs the collection, and prints the run summary. The operator's
    workstation must be domain-joined and have network connectivity to all target
    domain controllers.

.NOTES
    Requirements
    ────────────
    • PowerShell 7.1 or later (Windows edition — enforced via #Requires).
    • ActiveDirectory module from RSAT (Remote Server Administration Tools).
      Install via: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory*
    • Read access to Active Directory for all domains in scope.
    • Designed to run from an operator workstation; does NOT require execution
      on a domain controller.

    Module loading
    ──────────────
    The ActiveDirectory module is not natively compatible with PowerShell 7.
    The script auto-detects whether the installed module declares Core
    compatibility and loads it with -UseWindowsPowerShell when necessary,
    leveraging PS7's Windows PowerShell Compatibility Layer.

    CSV encoding
    ────────────
    All CSV files are written in UTF-8 without BOM. Fields containing commas,
    double-quotes, or newlines are automatically RFC 4180-compliant quoted.
    objectClass (a multi-valued AD attribute) is serialised as a
    semicolon-delimited string (e.g. "top;person;computer").

    Consolidated CSV
    ────────────────
    A forest-wide consolidated CSV is generated only when the selected scope
    covers more than one domain (options 1 and 3). For a single-domain run
    (option 2) the per-domain CSV already contains the full result set and no
    consolidated file is created.

    Visual feedback
    ───────────────
    • Initialisation phase (module load + forest discovery): Write-Progress bar
      (Id 0) so the console is never visually idle during slow AD queries.
    • Collection phase: outer progress bar (Id 1) on the main thread tracks
      domain-level progress across the scope. Per-object inner bars are not
      shown during parallel execution (not reliably supported across runspaces).
    • Console log lines are colour-coded by level:
        OK → Green   WARN → Yellow   ERROR → Red   INFO → Cyan
    • End-of-run boxed summary (Write-Host) is visually separated from the log
      stream and reports: elapsed time, scope, domains OK/error, total records,
      and output paths. Box colour is green on a clean run, yellow if any domain
      encountered errors.

    Logging
    ───────
    The general log file is created immediately at script start. A structured
    header block is written before any activity, containing: script name and
    version, start timestamp, hostname, and username. Once scope is confirmed,
    the selected domains are appended to the header.
    A footer block is written as the last operation before the writers are
    closed, containing: end timestamp, total elapsed time (hh:mm:ss), domain
    OK/error counts, and total records collected. This makes each log file
    fully self-contained for auditing without needing to cross-reference
    other files.

    Performance
    ───────────
    • Domains are collected concurrently via ForEach-Object -Parallel.
      ThrottleLimit = Min(domainCount, ProcessorCount) to avoid over-subscribing
      the operator's workstation.
    • Each parallel worker owns its own per-domain StreamWriter; no locking
      required for domain-level CSV writes.
    • The consolidated CSV is written inline per record from each worker,
      guarded by a System.Threading.Mutex — no end-of-run Export-Csv pass.
    • Domain success/error counters use Interlocked.Increment() for race-free
      updates across threads.
    • CSV field escaping uses a foreach loop instead of a ForEach-Object
      pipeline, eliminating per-record pipeline overhead.

    Author
    ──────
    Marco Farias

# ─────────────────────────────────────────────────────────────────────────────
# CHANGELOG
# ─────────────────────────────────────────────────────────────────────────────
#
# v4.1.0 — 2026-03 — Log header and footer
#   ADDED
#     • General log header written immediately after the StreamWriter is opened,
#       before any other activity. Contains: script name + version, start
#       timestamp, hostname, and username.
#     • Scope line appended to the header once the operator confirms the
#       selection, completing the header block.
#     • General log footer written just before Close-LogWriters. Contains: end
#       timestamp, total elapsed time (hh:mm:ss), domains OK/error count, and
#       total records collected. Makes the log self-contained — no need to
#       compare first and last lines to determine run duration.
#
# v4.0.0 — 2026-03 — Performance optimisations
#   CHANGED
#     • Domain collection loop replaced with ForEach-Object -Parallel — all
#       domains are now queried concurrently. ThrottleLimit is set to
#       Min(domainCount, ProcessorCount) to avoid over-subscribing the host.
#     • $Consolidado changed from List<PSCustomObject> to
#       ConcurrentBag<PSCustomObject> to support safe concurrent Add() from
#       parallel worker threads without locking.
#     • $domOK / $domError counters converted to [ref] int incremented via
#       Interlocked.Increment(), removing all shared-state races between workers.
#     • CSV field escaping moved from a ForEach-Object pipeline to a foreach
#       loop over a pre-built array, eliminating pipeline overhead on every
#       object record.
#     • Consolidated CSV now written inline per record inside each parallel
#       worker (guarded by a System.Threading.Mutex) instead of a single
#       Export-Csv call at the end. Eliminates the end-of-run memory flush and
#       makes the consolidated file readable in real time.
#     • Write-Progress (Id 2 inner bar) removed from parallel workers — not
#       supported reliably across parallel runspaces; outer progress (Id 1)
#       retained on main thread via syncProgress hashtable.
#   ADDED
#     • Write-ParallelLog inner function defined inside the parallel scriptblock
#       — each worker opens a short-lived StreamWriter per general-log append to
#       avoid cross-thread StreamWriter sharing.
#     • ConvertTo-CsvFieldLocal helper redefined inside the parallel scriptblock
#       (functions are not accessible across runspace boundaries via $using:).
#     • consolidatedMutex (System.Threading.Mutex) guards concurrent writes to
#       the shared consolidated StreamWriter; disposed after collection completes.
#     • objectClass null-check removed — the attribute is always present on
#       computer objects; direct @($c.objectClass) -join ';' used instead.
#
# v3.0.0 — 2026-03 — Interactive scope-selection menu & visual feedback pass
#   ADDED
#     • Interactive menu presented at startup with three scope options:
#         [1] Entire forest (all domains collected automatically).
#         [2] Single domain (operator selects one from a numbered list).
#         [3] Multiple domains (operator enters comma-separated numbers).
#     • Show-ScopeMenu helper: renders the scope menu and returns the
#       operator's validated choice.
#     • Select-SingleDomain helper: renders the domain list and returns
#       the single validated domain chosen by the operator.
#     • Select-MultipleDomains helper: renders the domain list and returns
#       two or more validated domains chosen by the operator.
#     • Show-DomainList helper: shared numbered-list renderer used by both
#       domain-selection helpers.
#     • Confirmation prompt after scope selection — operator must press Enter
#       before collection starts, preventing accidental runs.
#     • Write-Progress added to module-load and forest-discovery phases so the
#       console is never visually idle during slow AD queries.
#     • Write-Progress added to the consolidated CSV export phase.
#     • Run summary rendered as a distinct boxed block (Write-Host) fully
#       separated from the log stream, with per-status colour coding.
#     • Domain error/success counters tracked throughout collection and
#       reported in the summary: domains OK, domains with errors, skipped.
#     • Input validation loops on all prompts — invalid entries re-prompt
#       without exiting the script.
#     • Consolidated CSV is now conditional — generated only when more than
#       one domain is in scope; skipped (with an INFO log entry) for
#       single-domain runs.
#     • Scope label included in the run summary log for traceability.
#   CHANGED
#     • .DESCRIPTION expanded: confirmation prompt and end-of-run boxed summary
#       documented; flow description updated to match current startup sequence.
#     • .EXAMPLE rewritten to reflect the full run flow: module load → forest
#       discovery → scope menu → confirmation → collection → summary.
#     • .NOTES — new "Visual feedback" section added documenting all progress
#       bars (Id 0 / Id 1 / Id 2), console colour coding, and boxed summary
#       behaviour (green on clean run, yellow on partial errors).
#     • .NOTES — "Consolidated CSV" section updated to clarify that no
#       consolidated file is produced for single-domain runs.
#     • Forest discovery moved before logging initialisation so the full
#       domain list is available for the menu prior to any file I/O.
#     • $AllDomains sorted alphabetically for consistent list presentation.
#     • Outer Write-Progress activity label updated to reflect configurable
#       scope instead of always reading "Forest collection".
#     • $domOK and $domError counters introduced — incremented per domain
#       throughout the collection loop and consumed by the summary block.
#
# v2.0.0 — 2026-03 — Refactor & PS 7.1+ compatibility pass
#   BREAKING
#     • Minimum runtime raised to PowerShell 7.1 (enforced via #Requires).
#       Windows PowerShell 5.x is no longer supported.
#   FIXED
#     • Get-ADComputer single-object result no longer causes .Count failure;
#       result is always coerced to an array with @().
#     • Eliminated $saidaDomEnum assignment-from-foreach pattern, which left
#       the variable undefined under Set-StrictMode -Version Latest when the
#       domain returned zero objects.
#     • objectClass (multi-valued) now serialised as "a;b;c" instead of
#       rendering as "System.Object[]" in CSV output.
#   CHANGED
#     • ActiveDirectory module loading now inspects CompatiblePSEditions before
#       deciding whether to use -UseWindowsPowerShell, preventing silent import
#       failures on environments where the module is Core-compatible.
#     • Per-domain CSV files are now written record-by-record via
#       System.IO.StreamWriter (AutoFlush = true) instead of collecting all
#       objects in memory and calling Export-Csv at the end.
#     • Log files (general + per-domain) now use dedicated StreamWriter
#       instances with AutoFlush = true, opened at script start.
#     • Write-Progress restructured into two hierarchical levels:
#         Id 1 — forest-level progress (outer loop over domains).
#         Id 2 (ParentId 1) — domain-level progress (inner loop over objects).
#     • Write-Host output colour-coded by log level:
#         OK → Green  WARN → Yellow  ERROR → Red  INFO → Cyan
#     • Execution summary block added at end: elapsed time, total records,
#       output and log paths.
#     • All user-facing strings and inline comments translated to English.
#   ADDED
#     • Close-LogWriters helper: explicit Flush()/Close() on all StreamWriter
#       instances at script end and on early-exit error paths.
#     • Get-DomainLogWriter helper: lazy-initialises and caches per-domain
#       StreamWriter instances.
#
# v1.0.0 — 2025-06 — Initial release
#   • Forest discovery via Get-ADForest.
#   • Per-domain collection with -ResultPageSize 2000 and -Server $dom.
#   • Dual logging (general + per-domain) via Tee-Object.
#   • Forest-wide consolidated CSV via Export-Csv.
#   • Basic Write-Progress feedback (single level).
# ─────────────────────────────────────────────────────────────────────────────
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region ── Environment checks ────────────────────────────────────────────────
if (-not $IsWindows) {
    throw "This script requires Windows. The ActiveDirectory module is not available on other platforms."
}
#endregion

#region ── Output / log directories ──────────────────────────────────────────
$BaseCsvOut = 'C:\Temp\OutputScripts\Computers'
$BaseLogs   = 'C:\Temp\LogScripts\Computers'

foreach ($p in @($BaseCsvOut, $BaseLogs)) {
    if (-not (Test-Path $p)) {
        New-Item -Path $p -ItemType Directory -Force | Out-Null
    }
}

$RunStamp    = Get-Date -Format 'yyyyMMdd_HHmmss'
$CollectedAt = Get-Date
$LogGeral    = Join-Path $BaseLogs ("Computers_Forest_{0}.log" -f $RunStamp)

# Create the general log file immediately to ensure real-time writes from the first entry
$null = New-Item -Path $LogGeral -ItemType File -Force
#endregion

#region ── Logging ───────────────────────────────────────────────────────────
# Shared StreamWriter for the general log — synchronous writes, no buffering
$script:LogGeralWriter = [System.IO.StreamWriter]::new(
    $LogGeral,
    $true,                                    # append mode
    [System.Text.Encoding]::UTF8
)
$script:LogGeralWriter.AutoFlush = $true

# Write log header immediately — establishes start timestamp before any activity
$script:LogGeralWriter.WriteLine("# ═══════════════════════════════════════════════════════════════")
$script:LogGeralWriter.WriteLine("# Script  : Get-ADComputers_Forest.ps1  v4.0.0")
$script:LogGeralWriter.WriteLine("# Started : {0}" -f ($CollectedAt.ToString('yyyy-MM-dd HH:mm:ss')))
$script:LogGeralWriter.WriteLine("# Host    : {0}  ({1})" -f $env:COMPUTERNAME, $env:USERNAME)
$script:LogGeralWriter.WriteLine("# ═══════════════════════════════════════════════════════════════")

# Per-domain writer cache
$script:DomWriters = [System.Collections.Generic.Dictionary[string, System.IO.StreamWriter]]::new()

function Get-DomainLogWriter {
    param([string]$DomainTag)
    if (-not $script:DomWriters.ContainsKey($DomainTag)) {
        $logPath = Join-Path $BaseLogs ("Computers_{0}_{1}.log" -f ($DomainTag -replace '[^\w\-\.]', '-'), $RunStamp)
        $null = New-Item -Path $logPath -ItemType File -Force
        $w = [System.IO.StreamWriter]::new($logPath, $true, [System.Text.Encoding]::UTF8)
        $w.AutoFlush = $true
        $script:DomWriters[$DomainTag] = $w
    }
    return $script:DomWriters[$DomainTag]
}

function Close-LogWriters {
    $script:LogGeralWriter.Flush()
    $script:LogGeralWriter.Close()
    foreach ($w in $script:DomWriters.Values) {
        $w.Flush()
        $w.Close()
    }
}

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'OK')][string]$Level = 'INFO',
        [string]$DomainTag = ''
    )

    $ts   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $tag  = if ($DomainTag) { "[{0}]" -f $DomainTag } else { '          ' }
    $line = "[{0}] [{1,-5}] {2} {3}" -f $ts, $Level, $tag, $Message

    # Console colour per log level
    $color = switch ($Level) {
        'OK'    { 'Green'  }
        'WARN'  { 'Yellow' }
        'ERROR' { 'Red'    }
        default { 'Cyan'   }
    }

    Write-Host $line -ForegroundColor $color

    # General log — synchronous / real-time
    try { $script:LogGeralWriter.WriteLine($line) } catch { <# do not interrupt flow #> }

    # Domain log — synchronous / real-time
    if ($DomainTag) {
        try { (Get-DomainLogWriter -DomainTag $DomainTag).WriteLine($line) } catch { <# idem #> }
    }
}
#endregion

#region ── ActiveDirectory module ────────────────────────────────────────────
Write-Progress -Id 0 -Activity "Initialising" -Status "Loading ActiveDirectory module..." -PercentComplete 10
Write-Log "Loading ActiveDirectory module..."

try {
    $adAvailable = Get-Module -ListAvailable -Name ActiveDirectory | Select-Object -First 1
    if (-not $adAvailable) {
        throw "ActiveDirectory module not found. Install RSAT: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory*"
    }

    # Determine whether the module natively supports PowerShell Core
    $supportsCore = $adAvailable.CompatiblePSEditions -contains 'Core'

    if ($supportsCore) {
        Import-Module ActiveDirectory -ErrorAction Stop
        Write-Log "ActiveDirectory module loaded natively (Core)." -Level OK
    } else {
        Import-Module ActiveDirectory -UseWindowsPowerShell -ErrorAction Stop
        Write-Log "ActiveDirectory module loaded via Windows PowerShell Compatibility Layer." -Level OK
    }
} catch {
    Write-Progress -Id 0 -Activity "Initialising" -Completed
    Write-Log "Failed to load the ActiveDirectory module: $($_.Exception.Message)" -Level ERROR
    Close-LogWriters
    throw
}
#endregion

#region ── Forest discovery ───────────────────────────────────────────────────
Write-Progress -Id 0 -Activity "Initialising" -Status "Querying Active Directory forest..." -PercentComplete 50
Write-Log "Querying Active Directory forest..."

try {
    $Forest     = Get-ADForest
    $AllDomains = @($Forest.Domains | Sort-Object)   # sorted alphabetically; always an array

    if ($AllDomains.Count -eq 0) {
        throw "No domains found in the forest."
    }

    Write-Log ("Forest   : {0}" -f $Forest.Name) -Level OK
    Write-Log ("Domains  : {0} found — {1}" -f $AllDomains.Count, ($AllDomains -join ', ')) -Level OK
} catch {
    Write-Progress -Id 0 -Activity "Initialising" -Completed
    Write-Log "Error retrieving forest information: $($_.Exception.Message)" -Level ERROR
    Close-LogWriters
    throw
}

Write-Progress -Id 0 -Activity "Initialising" -Status "Ready." -PercentComplete 100
Start-Sleep -Milliseconds 400   # brief pause so the operator sees the completed bar
Write-Progress -Id 0 -Activity "Initialising" -Completed
#endregion

#region ── Scope-selection menu ──────────────────────────────────────────────
function Show-ScopeMenu {
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════╗" -ForegroundColor White
    Write-Host "  ║      AD Computer Collection — Select Scope       ║" -ForegroundColor White
    Write-Host "  ╠══════════════════════════════════════════════════╣" -ForegroundColor White
    Write-Host "  ║  [1]  Entire forest                              ║" -ForegroundColor White
    Write-Host "  ║  [2]  Single domain                              ║" -ForegroundColor White
    Write-Host "  ║  [3]  Multiple domains                           ║" -ForegroundColor White
    Write-Host "  ╚══════════════════════════════════════════════════╝" -ForegroundColor White
    Write-Host ""

    while ($true) {
        $choice = (Read-Host "  Select an option [1-3]").Trim()
        if ($choice -in @('1', '2', '3')) { return $choice }
        Write-Host "  Invalid option. Please enter 1, 2, or 3." -ForegroundColor Yellow
    }
}

function Show-DomainList {
    param([string[]]$Domains)

    Write-Host ""
    Write-Host "  Available domains:" -ForegroundColor White
    Write-Host "  ──────────────────────────────────────────────────" -ForegroundColor DarkGray
    for ($i = 0; $i -lt $Domains.Count; $i++) {
        Write-Host ("  [{0,2}]  {1}" -f ($i + 1), $Domains[$i]) -ForegroundColor Cyan
    }
    Write-Host "  ──────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""
}

function Select-SingleDomain {
    param([string[]]$Domains)

    Show-DomainList -Domains $Domains

    while ($true) {
        $input = (Read-Host "  Enter the domain number [1-$($Domains.Count)]").Trim()
        if ($input -match '^\d+$') {
            $idx = [int]$input - 1
            if ($idx -ge 0 -and $idx -lt $Domains.Count) {
                return @($Domains[$idx])
            }
        }
        Write-Host ("  Invalid selection. Please enter a number between 1 and {0}." -f $Domains.Count) -ForegroundColor Yellow
    }
}

function Select-MultipleDomains {
    param([string[]]$Domains)

    Show-DomainList -Domains $Domains

    while ($true) {
        $raw = (Read-Host "  Enter domain numbers separated by commas (e.g. 1,3)").Trim()

        # Parse and deduplicate entries
        $parts   = $raw -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
        $valid   = $true
        $indices = [System.Collections.Generic.List[int]]::new()

        foreach ($p in $parts) {
            if ($p -match '^\d+$') {
                $idx = [int]$p - 1
                if ($idx -ge 0 -and $idx -lt $Domains.Count) {
                    if (-not $indices.Contains($idx)) { $indices.Add($idx) }
                    continue
                }
            }
            $valid = $false
            break
        }

        if ($valid -and $indices.Count -ge 2) {
            return @($indices | Sort-Object | ForEach-Object { $Domains[$_] })
        }

        if (-not $valid -or $indices.Count -eq 0) {
            Write-Host ("  Invalid input. Use numbers between 1 and {0}, separated by commas." -f $Domains.Count) -ForegroundColor Yellow
        } else {
            Write-Host "  Please select at least two domains." -ForegroundColor Yellow
        }
    }
}

# ── Present menu and resolve the target domain list ───────────────────────────
$scopeChoice = Show-ScopeMenu

$TargetDomains = switch ($scopeChoice) {
    '1' {
        Write-Host ""
        Write-Host ("  Scope: Entire forest ({0} domains)" -f $AllDomains.Count) -ForegroundColor Green
        $AllDomains
    }
    '2' {
        $sel = Select-SingleDomain -Domains $AllDomains
        Write-Host ""
        Write-Host ("  Scope: Single domain — {0}" -f $sel[0]) -ForegroundColor Green
        $sel
    }
    '3' {
        $sel = Select-MultipleDomains -Domains $AllDomains
        Write-Host ""
        Write-Host ("  Scope: Multiple domains — {0}" -f ($sel -join ', ')) -ForegroundColor Green
        $sel
    }
}

Write-Host ""
Write-Log ("Scope selected: [{0}] — Domains in scope: {1}" -f $scopeChoice, ($TargetDomains -join ', '))

# Complete the log header now that scope is known
$script:LogGeralWriter.WriteLine("# Scope   : [{0}] — {1}" -f $scopeChoice, ($TargetDomains -join ', '))
$script:LogGeralWriter.WriteLine("# ───────────────────────────────────────────────────────────────")

# ── Confirmation before starting collection ───────────────────────────────────
Write-Host ""
Write-Host "  ──────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host "  Ready to start collection. Press Enter to continue or Ctrl+C to abort." -ForegroundColor Yellow
Write-Host "  ──────────────────────────────────────────────────" -ForegroundColor DarkGray
$null = Read-Host
#endregion

#region ── Per-domain collection ─────────────────────────────────────────────
$Attrs = @(
    'cn', 'distinguishedName', 'objectClass', 'lastLogonDate', 'lastLogonTimestamp',
    'pwdLastSet', 'userAccountControl', 'location', 'operatingSystem', 'displayName'
)

# Thread-safe bag — populated concurrently by parallel workers
$Consolidado = [System.Collections.Concurrent.ConcurrentBag[PSCustomObject]]::new()

# Thread-safe counters
$domOK    = [System.Threading.ThreadSafe]::new(0)   # see increment below via Interlocked
$domError = [System.Threading.ThreadSafe]::new(0)
# Using simple [ref] ints with Interlocked for PS7 compatibility
$domOKRef    = [ref]0
$domErrorRef = [ref]0

$domTotal = $TargetDomains.Count

# Outer progress is managed from the main thread via a synchronized hashtable
$syncProgress = [hashtable]::Synchronized(@{ Completed = 0; Total = $domTotal })

# ── Inline CSV-escape helper (avoids pipeline overhead per field) ─────────────
function ConvertTo-CsvField {
    param([object]$Value)
    $v = if ($null -eq $Value) { '' } else { $Value.ToString() }
    if ($v -match '[",\r\n]') { return '"{0}"' -f $v.Replace('"', '""') }
    return $v
}

# ── Consolidated StreamWriter — written inline, no final Export-Csv needed ────
$consolidatedCsvWriter = $null
if ($TargetDomains.Count -gt 1) {
    $csvForest             = Join-Path $BaseCsvOut ("COMPUTERS_FOREST_{0}.csv" -f $RunStamp)
    $consolidatedCsvWriter = [System.IO.StreamWriter]::new($csvForest, $false, [System.Text.Encoding]::UTF8)
    $consolidatedCsvWriter.AutoFlush = $true

    $consolidatedHeader = 'CN,DistinguishedName,ObjectClass,LastLogonDate,LastLogonTimestamp,' +
                          'pwdLastSet,userAccountControl,location,OperatingSystem,displayName,' +
                          'Domain,CollectedAt'
    $consolidatedCsvWriter.WriteLine($consolidatedHeader)
}

# Mutex to serialise writes to the consolidated StreamWriter across parallel threads
$consolidatedMutex = [System.Threading.Mutex]::new($false)

Write-Log ("━━━ Starting parallel collection across {0} domain(s)..." -f $domTotal)

$TargetDomains | ForEach-Object -Parallel {
    # ── Re-import variables from parent scope ────────────────────────────────
    $dom                   = $_
    $BaseCsvOut            = $using:BaseCsvOut
    $BaseLogs              = $using:BaseLogs
    $RunStamp              = $using:RunStamp
    $CollectedAt           = $using:CollectedAt
    $Attrs                 = $using:Attrs
    $Consolidado           = $using:Consolidado
    $domOKRef              = $using:domOKRef
    $domErrorRef           = $using:domErrorRef
    $syncProgress          = $using:syncProgress
    $consolidatedCsvWriter = $using:consolidatedCsvWriter
    $consolidatedMutex     = $using:consolidatedMutex
    $LogGeral              = $using:LogGeral

    # ── Thread-local log writer helpers ──────────────────────────────────────
    # Each parallel thread gets its own per-domain log writer.
    # The general log uses a per-call StreamWriter append to stay thread-safe.
    function Write-ParallelLog {
        param(
            [string]$Message,
            [string]$Level     = 'INFO',
            [string]$DomainTag = '',
            [string]$LogGeralPath,
            [System.IO.StreamWriter]$DomWriter
        )
        $ts   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        $tag  = if ($DomainTag) { "[{0}]" -f $DomainTag } else { '          ' }
        $line = "[{0}] [{1,-5}] {2} {3}" -f $ts, $Level, $tag, $Message

        $color = switch ($Level) {
            'OK'    { 'Green'  }
            'WARN'  { 'Yellow' }
            'ERROR' { 'Red'    }
            default { 'Cyan'   }
        }
        Write-Host $line -ForegroundColor $color

        # Append to general log — new StreamWriter per call to avoid cross-thread sharing
        try {
            $gw = [System.IO.StreamWriter]::new($LogGeralPath, $true, [System.Text.Encoding]::UTF8)
            $gw.AutoFlush = $true
            $gw.WriteLine($line)
            $gw.Close()
        } catch { }

        if ($null -ne $DomWriter) {
            try { $DomWriter.WriteLine($line) } catch { }
        }
    }

    # ── Inline CSV-escape (redefined inside parallel scope) ──────────────────
    function ConvertTo-CsvFieldLocal {
        param([object]$Value)
        $v = if ($null -eq $Value) { '' } else { $Value.ToString() }
        if ($v -match '[",\r\n]') { return '"{0}"' -f $v.Replace('"', '""') }
        return $v
    }

    # ── Per-domain log writer ─────────────────────────────────────────────────
    $domLogPath = Join-Path $BaseLogs ("Computers_{0}_{1}.log" -f ($dom -replace '[^\w\-\.]', '-'), $RunStamp)
    $null = New-Item -Path $domLogPath -ItemType File -Force
    $domWriter = [System.IO.StreamWriter]::new($domLogPath, $true, [System.Text.Encoding]::UTF8)
    $domWriter.AutoFlush = $true

    Write-ParallelLog -Message ("━━━ Starting domain: {0}" -f $dom) `
                      -LogGeralPath $LogGeral -DomWriter $domWriter

    $csvWriter = $null

    try {
        # ── AD query ─────────────────────────────────────────────────────────
        $rawComputers = Get-ADComputer -Server $dom -Filter * `
                                       -Properties $Attrs `
                                       -ResultPageSize 2000 `
                                       -ResultSetSize $null

        $computers = @($rawComputers)
        $total     = $computers.Count

        Write-ParallelLog -Message ("Computer objects found: {0}" -f $total) `
                          -Level OK -DomainTag $dom -LogGeralPath $LogGeral -DomWriter $domWriter

        # ── Domain CSV StreamWriter ───────────────────────────────────────────
        $csvDom    = Join-Path $BaseCsvOut ("COMPUTERS_{0}_{1}.csv" -f ($dom -replace '[^\w\-\.]', '-'), $RunStamp)
        $csvWriter = [System.IO.StreamWriter]::new($csvDom, $false, [System.Text.Encoding]::UTF8)
        $csvWriter.AutoFlush = $true

        $csvHeader = 'CN,DistinguishedName,ObjectClass,LastLogonDate,LastLogonTimestamp,' +
                     'pwdLastSet,userAccountControl,location,OperatingSystem,displayName,' +
                     'Domain,CollectedAt'
        $csvWriter.WriteLine($csvHeader)

        $i = 0
        foreach ($c in $computers) {
            $i++

            # objectClass always present on computer objects — direct join, no null check
            $objClass = @($c.objectClass) -join ';'

            $row = [PSCustomObject]@{
                CN                 = $c.cn
                DistinguishedName  = $c.distinguishedName
                ObjectClass        = $objClass
                LastLogonDate      = $c.lastLogonDate
                LastLogonTimestamp = $c.lastLogonTimestamp
                pwdLastSet         = $c.pwdLastSet
                userAccountControl = $c.userAccountControl
                location           = $c.location
                OperatingSystem    = $c.operatingSystem
                displayName        = $c.displayName
                Domain             = $dom
                CollectedAt        = $CollectedAt
            }

            # Build CSV line via inline helper — no pipeline overhead
            $fields = @(
                $row.CN, $row.DistinguishedName, $row.ObjectClass,
                $row.LastLogonDate, $row.LastLogonTimestamp,
                $row.pwdLastSet, $row.userAccountControl,
                $row.location, $row.OperatingSystem, $row.displayName,
                $row.Domain, $row.CollectedAt
            )
            $csvParts = foreach ($f in $fields) { ConvertTo-CsvFieldLocal $f }
            $csvLine  = $csvParts -join ','

            # Write to domain CSV (thread-local writer — no lock needed)
            $csvWriter.WriteLine($csvLine)

            # Write to consolidated CSV (shared writer — mutex required)
            if ($null -ne $consolidatedCsvWriter) {
                $null = $consolidatedMutex.WaitOne()
                try   { $consolidatedCsvWriter.WriteLine($csvLine) }
                finally { $consolidatedMutex.ReleaseMutex() }
            }

            # Add to thread-safe bag
            $Consolidado.Add($row)
        }

        $csvWriter.Flush()
        $csvWriter.Close()

        if ($total -gt 0) {
            Write-ParallelLog -Message ("Domain CSV saved to: {0}" -f $csvDom) `
                              -Level OK -DomainTag $dom -LogGeralPath $LogGeral -DomWriter $domWriter
        } else {
            Write-ParallelLog -Message "No computer objects found; empty CSV file created." `
                              -Level WARN -DomainTag $dom -LogGeralPath $LogGeral -DomWriter $domWriter
        }

        $null = [System.Threading.Interlocked]::Increment($domOKRef)

    } catch {
        $null = [System.Threading.Interlocked]::Increment($domErrorRef)
        Write-ParallelLog -Message ("Collection error: {0}" -f $_.Exception.Message) `
                          -Level ERROR -DomainTag $dom -LogGeralPath $LogGeral -DomWriter $domWriter
        if ($null -ne $csvWriter) {
            try { $csvWriter.Flush(); $csvWriter.Close() } catch { }
        }
    } finally {
        $domWriter.Flush()
        $domWriter.Close()

        # Update shared progress counter (main thread reads this for Write-Progress)
        $null = [System.Threading.Interlocked]::Increment(([ref]$syncProgress.Completed))

        Write-ParallelLog -Message ("Domain collection finished: {0}" -f $dom) `
                          -Level OK -DomainTag $dom -LogGeralPath $LogGeral -DomWriter $null
    }

} -ThrottleLimit ([Math]::Min($domTotal, [Environment]::ProcessorCount))

# Retrieve final counter values from Interlocked refs
$domOK    = $domOKRef.Value
$domError = $domErrorRef.Value

Write-Progress -Id 1 -Activity "AD Computer Collection" -Completed
#endregion

#region ── Consolidated CSV (multi-domain scopes only) ───────────────────────
if ($null -ne $consolidatedCsvWriter) {
    $consolidatedCsvWriter.Flush()
    $consolidatedCsvWriter.Close()
    Write-Log ("Consolidated CSV saved to: {0}" -f $csvForest) -Level OK
} else {
    Write-Log "Single-domain scope — consolidated CSV skipped." -Level INFO
}
$consolidatedMutex.Dispose()
#endregion

#region ── Run summary ───────────────────────────────────────────────────────
$elapsed      = (Get-Date) - $CollectedAt
$summaryColor = if ($domError -gt 0) { 'Yellow' } else { 'Green' }

# Log the summary lines (goes to file)
Write-Log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
Write-Log ("Run completed in {0:mm\:ss} (mm:ss)."    -f $elapsed)                    -Level OK
Write-Log ("Scope                   : {0}"            -f ($TargetDomains -join ', ')) -Level OK
Write-Log ("Domains OK              : {0}/{1}"        -f $domOK, $domTotal)           -Level OK
Write-Log ("Domains with errors     : {0}/{1}"        -f $domError, $domTotal)        -Level $(if ($domError -gt 0) { 'WARN' } else { 'OK' })
Write-Log ("Total records collected : {0}"            -f $Consolidado.Count)          -Level OK
Write-Log ("CSV output directory    : {0}"            -f $BaseCsvOut)                 -Level OK
Write-Log ("Log directory           : {0}"            -f $BaseLogs)                   -Level OK
Write-Log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Boxed visual summary — visually distinct from the log stream
Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════╗" -ForegroundColor $summaryColor
Write-Host "  ║               RUN SUMMARY                        ║" -ForegroundColor $summaryColor
Write-Host "  ╠══════════════════════════════════════════════════╣" -ForegroundColor $summaryColor
Write-Host ("  ║  Elapsed          : {0,-30}║" -f ("{0:mm\:ss} (mm:ss)" -f $elapsed))  -ForegroundColor $summaryColor
Write-Host ("  ║  Scope            : {0,-30}║" -f ($TargetDomains -join ', '))          -ForegroundColor $summaryColor
Write-Host ("  ║  Domains OK       : {0,-30}║" -f ("{0}/{1}" -f $domOK, $domTotal))    -ForegroundColor $summaryColor

$errLine = "{0}/{1}" -f $domError, $domTotal
$errColor = if ($domError -gt 0) { 'Yellow' } else { $summaryColor }
Write-Host ("  ║  Domains w/ error : {0,-30}║" -f $errLine) -ForegroundColor $errColor

Write-Host ("  ║  Records collected: {0,-30}║" -f $Consolidado.Count)  -ForegroundColor $summaryColor
Write-Host ("  ║  CSV directory    : {0,-30}║" -f $BaseCsvOut)          -ForegroundColor $summaryColor
Write-Host ("  ║  Log directory    : {0,-30}║" -f $BaseLogs)            -ForegroundColor $summaryColor
Write-Host "  ╚══════════════════════════════════════════════════╝" -ForegroundColor $summaryColor
Write-Host ""
#endregion

#region ── Close log writers ─────────────────────────────────────────────────
# Write log footer — end timestamp and total elapsed time recorded in the file
$finishedAt  = Get-Date
$totalElapsed = $finishedAt - $CollectedAt
$script:LogGeralWriter.WriteLine("# ───────────────────────────────────────────────────────────────")
$script:LogGeralWriter.WriteLine("# Finished : {0}" -f $finishedAt.ToString('yyyy-MM-dd HH:mm:ss'))
$script:LogGeralWriter.WriteLine("# Elapsed  : {0:hh\:mm\:ss} (hh:mm:ss)" -f $totalElapsed)
$script:LogGeralWriter.WriteLine("# Domains OK / Error : {0} / {1}" -f $domOK, $domError)
$script:LogGeralWriter.WriteLine("# Records collected  : {0}" -f $Consolidado.Count)
$script:LogGeralWriter.WriteLine("# ═══════════════════════════════════════════════════════════════")

Close-LogWriters
#endregion
