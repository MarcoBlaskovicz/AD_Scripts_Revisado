<#
.SYNOPSIS
    Audit-KerberosWeakEncryption.ps1

.DESCRIPTION
    Audits Domain Controllers to detect weak encryption (RC4/DES) usage
    in Kerberos events 4768 and 4769, identifying legacy systems (e.g., Windows
    Server 2003, older applications) before definitively blocking RC4 in the
    Active Directory environment.

    Execution flow:
      1. Scope selection menu: Full forest, specific domain, or local server only
         (where the script is being executed).
         - "Current Server" mode [L]: auditpol and Get-WinEvent run locally,
           with no WinRM or remote access required.
      2. For each selected DC, validates whether Kerberos auditing is enabled.
         - If NOT enabled: alerts the administrator, records the DC in a TXT file and moves on.
      3. For each DC with active auditing, collects events 4768/4769 (last 30 days)
         filtering for weak encryption via XPath (Get-WinEvent — high performance).
      4. Exports results to CSV and generates an analysis report.
      5. Real-time execution logs.

    WEAK ENCRYPTION TYPES DETECTED:
      0x17 → RC4-HMAC       (most common in legacy environments)
      0x01 → DES-CBC-CRC
      0x03 → DES-CBC-MD5

    MONITORED EVENTS:
      4768 → Kerberos Authentication Service Request (TGT)
      4769 → Kerberos Service Ticket Request (TGS)

.NOTES
    Version       : 1.1
    Prerequisites : PowerShell 5.1+, RSAT-ActiveDirectory module,
                    remote access (RPC/DCOM) to DC Event Logs,
                    read permission on the Security Event Log on DCs.

    Output files:
      LOG  → C:\Temp\Eventos\<ScriptName>_<DateTime>.log
      CSV  → C:\Temp\Scripts\Eventos\<ScriptName>_<DateTime>.csv
      TXT  → C:\Temp\Eventos\DCs_SemAuditoria_<DateTime>.txt  (if any DCs lack auditing)
#>

#Requires -Version 5.1

[CmdletBinding()]
param()

# ==============================================================================
# SECTION 1 — GLOBAL SETTINGS AND CONSTANTS
# ==============================================================================

# Script name without extension (used to name output files)
$ScriptName = if ($MyInvocation.MyCommand.Name) {
    [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
} else {
    'Audit-KerberosWeakEncryption'
}

# Execution timestamp — safe format for file names
$RunTimestamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'

# ─── Output directories ────────────────────────────────────────────────────────
$LogDir = 'C:\Temp\Eventos'
$CSVDir = 'C:\Temp\Scripts\Eventos'

# ─── Output file paths ─────────────────────────────────────────────────────────
$LogFile      = Join-Path $LogDir "${ScriptName}_${RunTimestamp}.log"
$CSVFile      = Join-Path $CSVDir "${ScriptName}_${RunTimestamp}.csv"
$NoAuditTXT   = Join-Path $LogDir "DCs_SemAuditoria_${RunTimestamp}.txt"

# ─── Lookback period in days ───────────────────────────────────────────────────
$DaysBack = 30

# ─── Weak encryption types to filter (integer values) ─────────────────────────
#     Any event with TicketEncryptionType matching these values will be captured.
$WeakEncTypes = @(
    0x17,   # RC4-HMAC       — widely used by legacy systems
    0x01,   # DES-CBC-CRC    — deprecated since RFC 6649
    0x03    # DES-CBC-MD5    — deprecated since RFC 6649
)

# ─── Encryption type map for friendly display ──────────────────────────────────
$EncTypeMap = @{
    0x01 = 'DES-CBC-CRC'
    0x03 = 'DES-CBC-MD5'
    0x11 = 'AES128-CTS-HMAC-SHA1-96'
    0x12 = 'AES256-CTS-HMAC-SHA1-96'
    0x17 = 'RC4-HMAC'
    0x18 = 'RC4-HMAC-EXP'
    0xFF = 'RC4-MD4'
}

# ─── Kerberos audit subcategory GUIDs ─────────────────────────────────────────
#     Using GUIDs ensures language-independent operation (EN, PT, ES, etc.).
$AuditGUID_KerbAuth   = '{0CCE9242-69AE-11D9-BED3-505054503030}'   # → event 4768
$AuditGUID_KerbTicket = '{0CCE9240-69AE-11D9-BED3-505054503030}'   # → event 4769

# ─── Result collections ────────────────────────────────────────────────────────
$AllResults   = [System.Collections.Generic.List[PSObject]]::new()   # collected events
$DCsNoAudit   = [System.Collections.Generic.List[string]]::new()     # DCs without auditing

# ==============================================================================
# SECTION 2 — REAL-TIME LOGGING FUNCTION
# ==============================================================================

function Write-Log {
    <#
    .SYNOPSIS
        Writes a log entry to the console and log file in real time.
    .PARAMETER Message
        Log message text.
    .PARAMETER Level
        Severity level: INFO | WARNING | ERROR | SUCCESS | SECTION
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, Position = 0)]
        [AllowEmptyString()]
        [string]$Message,

        [Parameter()]
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'SUCCESS', 'SECTION')]
        [string]$Level = 'INFO'
    )

    $Ts    = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $Entry = "[$Ts][$Level] $Message"

    # Console color by severity level
    $Color = switch ($Level) {
        'INFO'    { 'Cyan'    }
        'WARNING' { 'Yellow'  }
        'ERROR'   { 'Red'     }
        'SUCCESS' { 'Green'   }
        'SECTION' { 'Magenta' }
        default   { 'White'   }
    }

    Write-Host $Entry -ForegroundColor $Color

    # Writes immediately to file (unbuffered) — real-time logging
    try {
        Add-Content -Path $LogFile -Value $Entry -Encoding UTF8 -ErrorAction Stop
    }
    catch {
        # Log failure must not interrupt main execution
        Write-Host "  [AVISO-INTERNO] Falha ao gravar no log: $_" -ForegroundColor DarkYellow
    }
}

# ==============================================================================
# SECTION 3 — DIRECTORY INITIALIZATION
# ==============================================================================

function Initialize-OutputDirectories {
    <#
    .SYNOPSIS
        Creates output directories if they do not exist.
    #>
    [CmdletBinding()]
    param()

    foreach ($Dir in @($LogDir, $CSVDir)) {
        if (-not (Test-Path -LiteralPath $Dir -PathType Container)) {
            try {
                New-Item -Path $Dir -ItemType Directory -Force | Out-Null
                # Before the log file exists, use Write-Host directly
                Write-Host "  [INFO] Diretorio criado: $Dir" -ForegroundColor Cyan
            }
            catch {
                Write-Host "  [ERRO] Nao foi possivel criar '$Dir': $_" -ForegroundColor Red
                throw
            }
        }
    }
}

# ==============================================================================
# SECTION 4 — SCOPE SELECTION MENU (FOREST / DOMAIN / LOCAL SERVER)
# ==============================================================================

function Show-ScopeMenu {
    <#
    .SYNOPSIS
        Displays an interactive menu for the administrator to select the analysis scope:
        full AD forest, a specific domain, or the local server only.
    .OUTPUTS
        [PSCustomObject] with:
          Mode        [string]   — 'Forest' | 'Domain' | 'Local'
          Domains     [string[]] — selected domains (empty in Local mode)
          LocalServer [string]   — local server name (populated in Local mode)
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    Write-Host ''
    Write-Host ('=' * 72) -ForegroundColor Magenta
    Write-Host '  AUDITORIA DE CRIPTOGRAFIA FRACA KERBEROS  (RC4 / DES)' -ForegroundColor Magenta
    Write-Host '  Identificacao de sistemas legados antes do bloqueio do RC4' -ForegroundColor DarkMagenta
    Write-Host ('=' * 72) -ForegroundColor Magenta
    Write-Host ''

    # Retrieves forest topology via .NET (does not depend on the AD module)
    Write-Host '  Obtendo topologia da floresta Active Directory...' -ForegroundColor DarkCyan
    try {
        $Forest  = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        $Domains = @($Forest.Domains | Select-Object -ExpandProperty Name | Sort-Object)
    }
    catch {
        Write-Host "  [ERRO] Nao foi possivel acessar a floresta AD: $_" -ForegroundColor Red
        throw
    }

    Write-Host ''
    Write-Host "  Floresta      : $($Forest.Name)" -ForegroundColor White
    Write-Host "  Total dominios: $($Domains.Count)" -ForegroundColor White
    Write-Host "  Servidor local: $($env:COMPUTERNAME)" -ForegroundColor White
    Write-Host ''
    Write-Host '  Selecione o escopo de analise:' -ForegroundColor Yellow
    Write-Host ''
    Write-Host ('  [0]  Toda a Floresta  ({0} dominio(s))' -f $Domains.Count) -ForegroundColor Yellow

    for ($i = 0; $i -lt $Domains.Count; $i++) {
        Write-Host ('  [{0}]  {1}' -f ($i + 1), $Domains[$i]) -ForegroundColor White
    }

    Write-Host ('  [L]  Servidor Atual  ({0})' -f $env:COMPUTERNAME) -ForegroundColor Cyan

    Write-Host ''
    Write-Host ('-' * 72) -ForegroundColor DarkGray

    # Loop until a valid input is received
    while ($true) {
        $Raw = Read-Host '  Digite o numero da opcao (ou L para servidor atual)'

        # Option: Local Server
        if ($Raw -match '^[Ll]$') {
            Write-Host "  >> Escopo: Servidor Atual ($($env:COMPUTERNAME))" -ForegroundColor Cyan
            return [PSCustomObject]@{
                Mode        = 'Local'
                Domains     = @()
                LocalServer = $env:COMPUTERNAME
            }
        }

        if ($Raw -match '^\d+$') {
            $N = [int]$Raw

            if ($N -eq 0) {
                Write-Host "  >> Escopo: Toda a Floresta ($($Domains.Count) dominio(s))" -ForegroundColor Yellow
                return [PSCustomObject]@{
                    Mode        = 'Forest'
                    Domains     = $Domains
                    LocalServer = $null
                }
            }
            elseif ($N -ge 1 -and $N -le $Domains.Count) {
                Write-Host "  >> Escopo: Dominio '$($Domains[$N - 1])'" -ForegroundColor Yellow
                return [PSCustomObject]@{
                    Mode        = 'Domain'
                    Domains     = @($Domains[$N - 1])
                    LocalServer = $null
                }
            }
        }

        Write-Host "  Opcao invalida. Digite um numero entre 0 e $($Domains.Count), ou 'L' para servidor atual." -ForegroundColor Red
    }
}

# ==============================================================================
# SECTION 5 — KERBEROS AUDIT POLICY VERIFICATION
# ==============================================================================

function Test-KerberosAuditPolicy {
    <#
    .SYNOPSIS
        Verifies whether the Kerberos audit subcategories are active on the given
        Domain Controller.

    .DESCRIPTION
        Connects to the DC via Invoke-Command and runs auditpol using subcategory GUIDs
        (language-independent):
          {0CCE9242...} → Kerberos Authentication Service   (event 4768)
          {0CCE9240...} → Kerberos Service Ticket Operations (event 4769)

        When the target DC is the local server, auditpol runs directly in the current
        process without requiring WinRM.

    .PARAMETER DCName
        FQDN or NetBIOS name of the Domain Controller.

    .OUTPUTS
        [PSCustomObject] with:
          BothEnabled   [bool]   — both subcategories active
          AuthEnabled   [bool]   — Kerberos Authentication Service (4768)
          TicketEnabled [bool]   — Kerberos Service Ticket Operations (4769)
          ConnectError  [string] — connectivity error message (if any)
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory)]
        [string]$DCName
    )

    Write-Log "  Verificando politica de auditoria Kerberos em: $DCName" -Level INFO

    # Detects whether the target DC is the local server — avoids WinRM dependency
    $IsLocalDC = ($DCName -eq $env:COMPUTERNAME) -or
                 ($DCName -ieq 'localhost') -or
                 ($DCName -eq '127.0.0.1')

    try {
        if ($IsLocalDC) {
            # Local execution: auditpol runs directly in the current process
            Write-Log "  Modo local: executando auditpol localmente em '$DCName'" -Level INFO
            $OutAuth   = & auditpol /get /subcategory:"$AuditGUID_KerbAuth"   2>&1
            $OutTicket = & auditpol /get /subcategory:"$AuditGUID_KerbTicket" 2>&1
            $AuditStatus = [PSCustomObject]@{
                AuthEnabled   = (($OutAuth   -join ' ') -match '\b(Success|Failure)\b')
                TicketEnabled = (($OutTicket -join ' ') -match '\b(Success|Failure)\b')
            }
        }
        else {
            $AuditStatus = Invoke-Command -ComputerName $DCName -ErrorAction Stop -ScriptBlock {
                param ([string]$GUIDAuth, [string]$GUIDTicket)

                # Checks whether the audit subcategory is active.
                # The presence of "Success" or "Failure" in the output indicates it is enabled.
                # Using the GUID avoids language dependency (EN, PT, ES, etc.).
                function Test-AuditSubcategory {
                    param ([string]$GUID)
                    $Out = & auditpol /get /subcategory:"$GUID" 2>&1
                    return ($Out -join ' ') -match '\b(Success|Failure)\b'
                }

                return [PSCustomObject]@{
                    AuthEnabled   = (Test-AuditSubcategory -GUID $GUIDAuth)
                    TicketEnabled = (Test-AuditSubcategory -GUID $GUIDTicket)
                }
            } -ArgumentList $AuditGUID_KerbAuth, $AuditGUID_KerbTicket
        }

        $BothOK = $AuditStatus.AuthEnabled -and $AuditStatus.TicketEnabled

        if ($BothOK) {
            Write-Log "  [OK] Auditoria Kerberos habilitada (4768 + 4769) em $DCName" -Level SUCCESS
        }
        else {
            if (-not $AuditStatus.AuthEnabled)   { Write-Log "  [!] Kerberos Authentication Service (4768) NAO auditada em $DCName"   -Level WARNING }
            if (-not $AuditStatus.TicketEnabled) { Write-Log "  [!] Kerberos Service Ticket Operations (4769) NAO auditada em $DCName" -Level WARNING }
        }

        return [PSCustomObject]@{
            BothEnabled   = $BothOK
            AuthEnabled   = $AuditStatus.AuthEnabled
            TicketEnabled = $AuditStatus.TicketEnabled
            ConnectError  = $null
        }
    }
    catch {
        Write-Log "  [ERRO] Nao foi possivel verificar auditoria em '$DCName': $_" -Level ERROR
        return [PSCustomObject]@{
            BothEnabled   = $false
            AuthEnabled   = $false
            TicketEnabled = $false
            ConnectError  = $_.Exception.Message
        }
    }
}

# ==============================================================================
# SECTION 6 — ENCRYPTION TYPE CONVERSION (STRING → INT)
# ==============================================================================

function ConvertFrom-EncTypeString {
    <#
    .SYNOPSIS
        Converts the TicketEncryptionType field value (may arrive as "0x17" or "23")
        to a comparable integer. Returns $null if the value is invalid.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }

    try {
        # Hexadecimal format with "0x" prefix (e.g., "0x17", "0x01")
        if ($Value -match '^0[xX]([0-9A-Fa-f]+)$') {
            return [Convert]::ToInt32($Matches[1], 16)
        }
        # Decimal format (e.g., "23", "1", "3")
        elseif ($Value -match '^-?\d+$') {
            return [int]$Value
        }
        return $null
    }
    catch {
        return $null
    }
}

# ==============================================================================
# SECTION 7 — KERBEROS EVENT COLLECTION AND FILTERING (4768 / 4769)
# ==============================================================================

function Get-WeakEncryptionEvents {
    <#
    .SYNOPSIS
        Collects events 4768 and 4769 from a Domain Controller's Security log
        and returns only those using weak encryption (RC4, DES).

    .DESCRIPTION
        Uses Get-WinEvent with an XPath filter for maximum performance:
          - The filter is evaluated on the remote server, reducing network traffic.
          - Only relevant events (4768/4769 in the time window) travel over the network.
          - Weak encryption type filtering is performed locally after parsing each event's XML.

        When the target DC is the local server, the Security log is read directly
        without requiring WinRM.

    .PARAMETER DCName
        Domain Controller name.

    .PARAMETER DaysBack
        Lookback time window in days (default: 30).

    .OUTPUTS
        [PSObject[]] Filtered event list with all relevant fields.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$DCName,

        [Parameter()]
        [ValidateRange(1, 365)]
        [int]$DaysBack = 30
    )

    Write-Log "  Coletando eventos 4768/4769 de '$DCName' (ultimos $DaysBack dias)..." -Level INFO

    # Converts start date to UTC ISO 8601 format required by the Event Log XPath filter
    $StartUTC = (Get-Date).AddDays(-$DaysBack).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.000Z')

    # ── Optimized XPath filter ─────────────────────────────────────────────────
    # Server-side filter: only EventIDs 4768/4769 in the time window → minimal traffic.
    # The &gt;= operator is the XML encoding of >=.
    $XPath = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[
        (EventID=4768 or EventID=4769)
        and TimeCreated[@SystemTime &gt;= '$StartUTC']
      ]]
    </Select>
  </Query>
</QueryList>
"@

    $LocalList  = [System.Collections.Generic.List[PSObject]]::new()
    [int]$TotalRaw  = 0
    [int]$WeakFound = 0

    # Detects whether the target DC is the local server — avoids WinRM dependency
    $IsLocalDC = ($DCName -eq $env:COMPUTERNAME) -or
                 ($DCName -ieq 'localhost') -or
                 ($DCName -eq '127.0.0.1')

    # ── Collect raw events via Get-WinEvent ────────────────────────────────────
    try {
        if ($IsLocalDC) {
            # Direct read from the local log — no network traffic
            Write-Log "  Modo local: lendo log de seguranca localmente em '$DCName'" -Level INFO
            $RawEvents = Get-WinEvent -FilterXml $XPath -ErrorAction Stop
        }
        else {
            $RawEvents = Get-WinEvent -ComputerName $DCName -FilterXml $XPath -ErrorAction Stop
        }
        $TotalRaw  = $RawEvents.Count
        Write-Log "  $TotalRaw evento(s) bruto(s) obtido(s) de '$DCName'. Processando..." -Level INFO
    }
    catch {
        # No events in the time window is a normal scenario, not an error
        if ($_.Exception.Message -match 'No events were found|nenhum evento') {
            Write-Log "  Nenhum evento 4768/4769 em '$DCName' no periodo de $DaysBack dias." -Level INFO
            return $LocalList
        }
        Write-Log "  [ERRO] Falha ao coletar eventos de '$DCName': $_" -Level ERROR
        return $LocalList
    }

    # ── Process each event: XML parse + weak encryption filtering ──────────────
    foreach ($Evt in $RawEvents) {
        try {
            # Parse event XML for granular access to EventData fields
            [xml]$EvtXml = $Evt.ToXml()

            # Build hashtable { FieldName → Value } from Data nodes
            $D = @{}
            foreach ($Node in $EvtXml.Event.EventData.Data) {
                $D[$Node.Name] = $Node.'#text'
            }

            # ── Extract and convert the encryption type ────────────────────────
            $EncRaw = if ($D.ContainsKey('TicketEncryptionType')) { $D['TicketEncryptionType'] } else { $null }
            $EncInt = ConvertFrom-EncTypeString -Value $EncRaw

            # Discard events without an encryption type (e.g., pre-authentication failed)
            if ($null -eq $EncInt) { continue }

            # ── Filter only WEAK encryption types ──────────────────────────────
            if ($EncInt -notin $WeakEncTypes) { continue }

            $WeakFound++

            # Friendly encryption type name for display/export
            $EncName = if ($EncTypeMap.ContainsKey($EncInt)) {
                '{0} (0x{1:X2})' -f $EncTypeMap[$EncInt], $EncInt
            }
            else {
                '0x{0:X2} (tipo desconhecido)' -f $EncInt
            }

            # Strip IPv4-mapped IPv6 prefix (::ffff:192.168.x.x → 192.168.x.x)
            $IP = ([string]($D['IpAddress'])) -replace '^::ffff:', '' -replace '^\s+|\s+$', ''

            # ── Build the structured result object ─────────────────────────────
            # [ordered] ensures field order in the exported CSV
            $Obj = [PSCustomObject][ordered]@{
                Timestamp                = $Evt.TimeCreated
                EventID                  = $Evt.Id

                # Account that requested the ticket
                AccountName              = [string]($D['TargetUserName'])
                AccountDomain            = [string]($D['TargetDomainName'])

                # Request origin (legacy system identification)
                ClientAddress            = $IP
                ClientPort               = [string]($D['IpPort'])

                # ServiceName: relevant only for 4769 (TGS). For 4768 (TGT) it is N/A.
                ServiceName              = if ($Evt.Id -eq 4769) {
                                               [string]($D['ServiceName'])
                                           } else {
                                               'N/A (TGT - evento 4768)'
                                           }

                # ─── MAIN FIELD: weak encryption type detected ─────────────────
                TicketEncryptionType     = $EncName
                EncryptionHex            = '0x{0:X2}' -f $EncInt

                # Event status (0x0 = success, others = Kerberos errors)
                Status                   = [string]($D['Status'])

                # Flag for quick identification of weak encryption
                WeakEncryption           = $true

                # Source DC — essential for locating where events originate
                DomainController         = $DCName
            }

            $LocalList.Add($Obj)
        }
        catch {
            # A failure on a single event does not interrupt collection of the remaining ones
            Write-Log "  [AVISO] Erro ao processar evento RecordId=$($Evt.RecordId): $_" -Level WARNING
            continue
        }
    }

    $LevelResult = if ($WeakFound -gt 0) { 'WARNING' } else { 'SUCCESS' }
    Write-Log "  Resultado '$DCName': $WeakFound evento(s) com cripto fraca de $TotalRaw total." -Level $LevelResult

    return $LocalList
}

# ==============================================================================
# SECTION 8 — ALERT FUNCTION: DC WITHOUT AUDITING
# ==============================================================================

function Write-AuditAlert {
    <#
    .SYNOPSIS
        Displays a highlighted visual alert on the console, writes to the log and TXT file
        when a DC does not have Kerberos auditing enabled.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)] [string]$DCName,
        [Parameter(Mandatory)] [string]$DomainName,
        [Parameter(Mandatory)] [PSCustomObject]$AuditStatus
    )

    $Border = '!' * 65

    Write-Host ''
    Write-Host $Border -ForegroundColor Red
    Write-Host "  ALERTA: Auditoria Kerberos INCOMPLETA / AUSENTE" -ForegroundColor Red
    Write-Host "  DC      : $DCName" -ForegroundColor Red
    Write-Host "  Dominio : $DomainName"  -ForegroundColor Red

    if (-not $AuditStatus.AuthEnabled) {
        Write-Host '  AUSENTE : Kerberos Authentication Service   (evento 4768)' -ForegroundColor Red
    }
    if (-not $AuditStatus.TicketEnabled) {
        Write-Host '  AUSENTE : Kerberos Service Ticket Operations (evento 4769)' -ForegroundColor Red
    }
    if ($AuditStatus.ConnectError) {
        Write-Host "  ERRO    : $($AuditStatus.ConnectError)" -ForegroundColor DarkRed
    }

    Write-Host ''
    Write-Host '  CORRECAO — Execute como Administrador no DC:' -ForegroundColor Yellow
    Write-Host '    auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable'    -ForegroundColor DarkYellow
    Write-Host '    auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable' -ForegroundColor DarkYellow
    Write-Host ''
    Write-Host '  Ou via GPO: Computer Configuration > Policies > Windows Settings >' -ForegroundColor DarkYellow
    Write-Host '              Security Settings > Advanced Audit Policy Configuration > Account Logon' -ForegroundColor DarkYellow
    Write-Host $Border -ForegroundColor Red
    Write-Host ''

    # Write to the execution log
    Write-Log "ALERTA: DC '$DCName' (dominio '$DomainName') sem auditoria Kerberos completa. Passando ao proximo DC." -Level WARNING

    # Write structured line to the no-auditing DCs TXT file
    $TxtLine = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Dominio: $DomainName | DC: $DCName"
    if (-not $AuditStatus.AuthEnabled)   { $TxtLine += ' | SEM: Kerberos Authentication Service (4768)' }
    if (-not $AuditStatus.TicketEnabled) { $TxtLine += ' | SEM: Kerberos Service Ticket Operations (4769)' }
    if ($AuditStatus.ConnectError)       { $TxtLine += " | ERRO CONEXAO: $($AuditStatus.ConnectError)" }

    try {
        Add-Content -Path $NoAuditTXT -Value $TxtLine -Encoding UTF8 -ErrorAction Stop
        Write-Log "  DC registrado em: $NoAuditTXT" -Level WARNING
    }
    catch {
        Write-Log "  Nao foi possivel gravar '$DCName' em '$NoAuditTXT': $_" -Level WARNING
    }
}

# ==============================================================================
# SECTION 9 — MAIN ENTRY POINT
# ==============================================================================

# Create directories before any logging (Write-Host is used internally)
Initialize-OutputDirectories

# ── Log header ─────────────────────────────────────────────────────────────────
Write-Log ('=' * 72)                                              -Level SECTION
Write-Log "SCRIPT   : $ScriptName"                               -Level SECTION
Write-Log "INICIO   : $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" -Level SECTION
Write-Log "LOG      : $LogFile"                                   -Level SECTION
Write-Log "CSV      : $CSVFile"                                   -Level SECTION
Write-Log "PERIODO  : Ultimos $DaysBack dias"                     -Level SECTION
Write-Log ('=' * 72)                                              -Level SECTION
Write-Log ''                                                      -Level INFO

# ── Check and import the Active Directory module ───────────────────────────────
if (-not (Get-Module -Name ActiveDirectory -ListAvailable -ErrorAction SilentlyContinue)) {
    Write-Log 'Modulo ActiveDirectory (RSAT) nao encontrado.' -Level ERROR
    Write-Log 'Para instalar: Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"' -Level INFO
    exit 1
}

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Log 'Modulo ActiveDirectory carregado com sucesso.' -Level SUCCESS
}
catch {
    Write-Log "Falha ao importar modulo ActiveDirectory: $_" -Level ERROR
    exit 1
}

# ── Display menu and retrieve the scope selected by the administrator ──────────
$Scope = Show-ScopeMenu

Write-Log '' -Level INFO
Write-Log "Escopo      : $(if ($Scope.Mode -eq 'Local') { "Servidor Atual ($($Scope.LocalServer))" } else { $Scope.Domains -join ' | ' })" -Level INFO
Write-Log "Cripto alvo : RC4-HMAC (0x17) | DES-CBC-CRC (0x01) | DES-CBC-MD5 (0x03)" -Level INFO
Write-Log '' -Level INFO

# ==============================================================================
# SECTION 10 — MAIN LOOP: DOMAINS → DCs → AUDITING → EVENTS
# ==============================================================================

if ($Scope.Mode -eq 'Local') {

    # ── Mode: Current Server ───────────────────────────────────────────────────
    $LocalServer = $Scope.LocalServer

    # Retrieves the local server's domain for alert display
    try {
        $LocalDomain = (Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop).Domain
    }
    catch {
        $LocalDomain = $env:USERDNSDOMAIN
        if (-not $LocalDomain) { $LocalDomain = 'Desconhecido' }
    }

    Write-Log ('=' * 72)                        -Level SECTION
    Write-Log "SERVIDOR LOCAL : $LocalServer"   -Level SECTION
    Write-Log "DOMINIO        : $LocalDomain"   -Level SECTION
    Write-Log ('=' * 72)                        -Level SECTION

    Write-Log ''                    -Level INFO
    Write-Log ('-' * 60)            -Level INFO
    Write-Log "DC: $LocalServer"    -Level INFO
    Write-Log ('-' * 60)            -Level INFO

    # STEP A — Kerberos audit policy verification (local)
    $Audit = Test-KerberosAuditPolicy -DCName $LocalServer

    if (-not $Audit.BothEnabled) {
        Write-AuditAlert -DCName $LocalServer -DomainName $LocalDomain -AuditStatus $Audit
        $DCsNoAudit.Add($LocalServer)
    }
    else {
        # STEP B — Collect events 4768/4769 with weak encryption (local)
        $Events = Get-WeakEncryptionEvents -DCName $LocalServer -DaysBack $DaysBack
        foreach ($E in $Events) {
            $AllResults.Add($E)
        }
    }

}
else {

    # ── Mode: Forest or Specific Domain ───────────────────────────────────────
    foreach ($Domain in $Scope.Domains) {

        Write-Log ('=' * 72)         -Level SECTION
        Write-Log "DOMINIO: $Domain" -Level SECTION
        Write-Log ('=' * 72)         -Level SECTION

        # ── Retrieve list of Domain Controllers for the domain ─────────────────
        try {
            [string[]]$DCs = Get-ADDomainController -Filter * -Server $Domain -ErrorAction Stop |
                             Select-Object -ExpandProperty HostName |
                             Sort-Object

            Write-Log "Domain Controllers encontrados em '$Domain': $($DCs.Count)" -Level INFO
            Write-Log "Lista: $($DCs -join ', ')" -Level INFO
        }
        catch {
            Write-Log "Erro ao listar DCs do dominio '$Domain': $_" -Level ERROR
            continue   # Move to the next domain
        }

        # ── Process each Domain Controller ─────────────────────────────────────
        foreach ($DC in $DCs) {

            Write-Log ''            -Level INFO
            Write-Log ('-' * 60)   -Level INFO
            Write-Log "DC: $DC"    -Level INFO
            Write-Log ('-' * 60)   -Level INFO

            # ══════════════════════════════════════════════════════════════════
            # STEP A — Kerberos audit policy verification
            # ══════════════════════════════════════════════════════════════════
            $Audit = Test-KerberosAuditPolicy -DCName $DC

            if (-not $Audit.BothEnabled) {
                # Alert, write to TXT and move to the next DC
                Write-AuditAlert -DCName $DC -DomainName $Domain -AuditStatus $Audit
                $DCsNoAudit.Add($DC)
                continue
            }

            # ══════════════════════════════════════════════════════════════════
            # STEP B — Collect events 4768/4769 with weak encryption
            # ══════════════════════════════════════════════════════════════════
            $Events = Get-WeakEncryptionEvents -DCName $DC -DaysBack $DaysBack

            foreach ($E in $Events) {
                $AllResults.Add($E)
            }

        }   # end foreach DC
    }       # end foreach Domain

}   # end if/else scope

# ==============================================================================
# SECTION 11 — CSV EXPORT AND FINAL REPORT
# ==============================================================================

Write-Log ''                    -Level INFO
Write-Log ('=' * 72)            -Level SECTION
Write-Log 'RELATORIO FINAL'     -Level SECTION
Write-Log ('=' * 72)            -Level SECTION

if ($AllResults.Count -gt 0) {

    Write-Log "Total de eventos com CRIPTOGRAFIA FRACA detectados: $($AllResults.Count)" -Level WARNING

    # ── Export CSV ─────────────────────────────────────────────────────────────
    try {
        $AllResults | Export-Csv -Path $CSVFile `
                                 -NoTypeInformation `
                                 -Encoding UTF8 `
                                 -Delimiter ';' `
                                 -ErrorAction Stop
        Write-Log "CSV exportado com sucesso: $CSVFile" -Level SUCCESS
    }
    catch {
        Write-Log "Erro ao exportar CSV: $_" -Level ERROR
    }

    # ── Summary by encryption type ─────────────────────────────────────────────
    Write-Log ''  -Level INFO
    Write-Log '[ RESUMO POR TIPO DE CRIPTOGRAFIA FRACA ]' -Level SECTION
    $AllResults |
        Group-Object EncryptionHex |
        Sort-Object Count -Descending |
        ForEach-Object {
            $DisplayName = switch ($_.Name) {
                '0x17' { 'RC4-HMAC              (0x17) *** MAIS COMUM ***' }
                '0x01' { 'DES-CBC-CRC           (0x01)' }
                '0x03' { 'DES-CBC-MD5           (0x03)' }
                default { $_.Name }
            }
            Write-Log ('  {0,-50} : {1,6} evento(s)' -f $DisplayName, $_.Count) -Level WARNING
        }

    # ── Summary by Domain Controller ───────────────────────────────────────────
    Write-Log ''  -Level INFO
    Write-Log '[ RESUMO POR DOMAIN CONTROLLER ]' -Level SECTION
    $AllResults |
        Group-Object DomainController |
        Sort-Object Count -Descending |
        ForEach-Object {
            Write-Log ('  {0,-55} : {1,6} evento(s)' -f $_.Name, $_.Count) -Level INFO
        }

    # ── Top 10 accounts with most weak encryption events ───────────────────────
    Write-Log ''  -Level INFO
    Write-Log '[ TOP 10 CONTAS — MAIOR VOLUME DE CRIPTO FRACA ]' -Level SECTION
    $AllResults |
        Group-Object AccountName |
        Sort-Object Count -Descending |
        Select-Object -First 10 |
        ForEach-Object {
            Write-Log ('  {0,-55} : {1,6} evento(s)' -f $_.Name, $_.Count) -Level WARNING
        }

    # ── Top 10 source IPs (probable legacy systems) ────────────────────────────
    Write-Log ''  -Level INFO
    Write-Log '[ TOP 10 IPs DE ORIGEM — PROVAVEIS SISTEMAS LEGADOS ]' -Level SECTION
    Write-Log '  (Enderecos que mais solicitaram tickets com criptografia fraca)' -Level INFO
    $AllResults |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_.ClientAddress) } |
        Group-Object ClientAddress |
        Sort-Object Count -Descending |
        Select-Object -First 10 |
        ForEach-Object {
            Write-Log ('  {0,-45} : {1,6} evento(s)  <- INVESTIGAR' -f $_.Name, $_.Count) -Level WARNING
        }

    # ── Console preview (first 50 records) ────────────────────────────────────
    Write-Host ''
    Write-Host ('PREVIEW — Primeiros 50 eventos com criptografia fraca detectada:') -ForegroundColor Red
    Write-Host ('  [!] Verifique o CSV para a lista completa: ' + $CSVFile) -ForegroundColor DarkRed
    Write-Host ''
    $AllResults |
        Select-Object -First 50 |
        Format-Table -AutoSize -Property Timestamp, EventID, AccountName, ClientAddress, ServiceName, TicketEncryptionType, DomainController
}
else {
    Write-Log 'Nenhum evento com criptografia fraca (RC4/DES) encontrado no periodo analisado.' -Level SUCCESS
    Write-Log 'O ambiente parece estar configurado corretamente para uso exclusivo de AES.' -Level SUCCESS
}

# ── Consolidated alert: DCs without auditing ──────────────────────────────────
if ($DCsNoAudit.Count -gt 0) {
    Write-Log ''  -Level INFO
    Write-Log ('!' * 72) -Level WARNING
    Write-Log "DCs SEM AUDITORIA KERBEROS COMPLETA: $($DCsNoAudit.Count) DC(s) foram ignorados" -Level WARNING
    foreach ($DCName in $DCsNoAudit) {
        Write-Log "  - $DCName" -Level WARNING
    }
    Write-Log "Lista completa salva em: $NoAuditTXT" -Level WARNING
    Write-Log ('!' * 72) -Level WARNING

    Write-Log ''  -Level INFO
    Write-Log '[ COMO HABILITAR A AUDITORIA ]' -Level SECTION
    Write-Log '  Via linha de comando (execute no DC como Administrador):' -Level INFO
    Write-Log '    auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable'    -Level INFO
    Write-Log '    auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable' -Level INFO
    Write-Log ''  -Level INFO
    Write-Log '  Via GPO (recomendado para multiplos DCs):' -Level INFO
    Write-Log '    Computer Configuration > Policies > Windows Settings > Security Settings >' -Level INFO
    Write-Log '    Advanced Audit Policy Configuration > Account Logon' -Level INFO
    Write-Log '      - Audit Kerberos Authentication Service    : Success e Failure' -Level INFO
    Write-Log '      - Audit Kerberos Service Ticket Operations : Success e Failure' -Level INFO
}

# ── Final footer ───────────────────────────────────────────────────────────────
Write-Log ''                                                              -Level INFO
Write-Log ('=' * 72)                                                      -Level SECTION
Write-Log 'EXECUCAO CONCLUIDA'                                            -Level SECTION
Write-Log "Data/Hora         : $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" -Level SECTION
Write-Log "Eventos exportados: $($AllResults.Count)"                      -Level SECTION
Write-Log "DCs sem auditoria : $($DCsNoAudit.Count)"                     -Level SECTION
Write-Log "Log de execucao   : $LogFile"                                  -Level SECTION

if ($AllResults.Count -gt 0) {
    Write-Log "CSV de resultados : $CSVFile" -Level SECTION
}
if ($DCsNoAudit.Count -gt 0) {
    Write-Log "TXT sem auditoria : $NoAuditTXT" -Level SECTION
}

Write-Log ('=' * 72) -Level SECTION
