<#
.SYNOPSIS
    Audit-KerberosWeakEncryption.ps1

.DESCRIPTION
    Audita Domain Controllers para detectar uso de criptografia fraca (RC4/DES)
    nos eventos Kerberos 4768 e 4769, identificando sistemas legados (ex.: Windows
    Server 2003, aplicações antigas) antes do bloqueio definitivo do RC4 no ambiente
    Active Directory.

    Fluxo de execução:
      1. Menu de seleção do escopo: Floresta completa, domínio específico ou
         apenas o servidor local (onde o script está sendo executado).
         - Modo "Servidor Atual" [L]: auditpol e Get-WinEvent rodam localmente,
           sem necessidade de WinRM ou acesso remoto.
      2. Para cada DC selecionado, valida se a auditoria Kerberos está habilitada.
         - Se NÃO estiver: alerta o administrador, grava o DC em TXT e passa ao próximo.
      3. Para cada DC com auditoria ativa, coleta eventos 4768/4769 (últimos 30 dias)
         filtrando por criptografia fraca via XPath (Get-WinEvent — alto desempenho).
      4. Exporta resultados para CSV e gera relatório de análise.
      5. Logs de execução em tempo real.

    CRIPTOGRAFIAS FRACAS DETECTADAS:
      0x17 → RC4-HMAC       (mais comum em ambientes legados)
      0x01 → DES-CBC-CRC
      0x03 → DES-CBC-MD5

    EVENTOS MONITORADOS:
      4768 → Kerberos Authentication Service Request (TGT)
      4769 → Kerberos Service Ticket Request (TGS)

.NOTES
    Versão        : 1.1
    Pré-requisitos: PowerShell 5.1+, módulo RSAT-ActiveDirectory,
                    acesso remoto (RPC/DCOM) ao Event Log dos DCs,
                    permissão de leitura do Security Event Log nos DCs.

    Saídas geradas:
      LOG  → C:\Temp\Eventos\<ScriptName>_<DataHora>.log
      CSV  → C:\Temp\Scripts\Eventos\<ScriptName>_<DataHora>.csv
      TXT  → C:\Temp\Eventos\DCs_SemAuditoria_<DataHora>.txt  (se houver DCs sem auditoria)
#>

#Requires -Version 5.1

[CmdletBinding()]
param()

# ==============================================================================
# SEÇÃO 1 — CONFIGURAÇÕES GLOBAIS E CONSTANTES
# ==============================================================================

# Nome do script sem extensão (usado para nomear arquivos de saída)
$ScriptName = if ($MyInvocation.MyCommand.Name) {
    [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
} else {
    'Audit-KerberosWeakEncryption'
}

# Timestamp da execução — formato seguro para nomes de arquivo
$RunTimestamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'

# ─── Diretórios de saída ───────────────────────────────────────────────────────
$LogDir = 'C:\Temp\Eventos'
$CSVDir = 'C:\Temp\Scripts\Eventos'

# ─── Caminhos dos arquivos de saída ────────────────────────────────────────────
$LogFile      = Join-Path $LogDir "${ScriptName}_${RunTimestamp}.log"
$CSVFile      = Join-Path $CSVDir "${ScriptName}_${RunTimestamp}.csv"
$NoAuditTXT   = Join-Path $LogDir "DCs_SemAuditoria_${RunTimestamp}.txt"

# ─── Período de análise retroativa (dias) ──────────────────────────────────────
$DaysBack = 30

# ─── Tipos de criptografia fraca que serão filtrados (valores inteiros) ────────
#     Qualquer evento com TicketEncryptionType nesses valores será capturado.
$WeakEncTypes = @(
    0x17,   # RC4-HMAC       — vastamente usado por sistemas legados
    0x01,   # DES-CBC-CRC    — obsoleto desde RFC 6649
    0x03    # DES-CBC-MD5    — obsoleto desde RFC 6649
)

# ─── Mapa de tipos de criptografia para exibição amigável ──────────────────────
$EncTypeMap = @{
    0x01 = 'DES-CBC-CRC'
    0x03 = 'DES-CBC-MD5'
    0x11 = 'AES128-CTS-HMAC-SHA1-96'
    0x12 = 'AES256-CTS-HMAC-SHA1-96'
    0x17 = 'RC4-HMAC'
    0x18 = 'RC4-HMAC-EXP'
    0xFF = 'RC4-MD4'
}

# ─── GUIDs das subcategorias de auditoria Kerberos ─────────────────────────────
#     O uso de GUIDs garante funcionamento independente do idioma do SO.
$AuditGUID_KerbAuth   = '{0CCE9242-69AE-11D9-BED3-505054503030}'   # → evento 4768
$AuditGUID_KerbTicket = '{0CCE9240-69AE-11D9-BED3-505054503030}'   # → evento 4769

# ─── Coleções de resultados ────────────────────────────────────────────────────
$AllResults   = [System.Collections.Generic.List[PSObject]]::new()   # eventos coletados
$DCsNoAudit   = [System.Collections.Generic.List[string]]::new()     # DCs sem auditoria

# ==============================================================================
# SEÇÃO 2 — FUNÇÃO DE LOGGING EM TEMPO REAL
# ==============================================================================

function Write-Log {
    <#
    .SYNOPSIS
        Grava uma entrada de log no console e no arquivo de log em tempo real.
    .PARAMETER Message
        Texto da mensagem a registrar.
    .PARAMETER Level
        Nível de severidade: INFO | WARNING | ERROR | SUCCESS | SECTION
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

    # Cor de exibição no console por nível de severidade
    $Color = switch ($Level) {
        'INFO'    { 'Cyan'    }
        'WARNING' { 'Yellow'  }
        'ERROR'   { 'Red'     }
        'SUCCESS' { 'Green'   }
        'SECTION' { 'Magenta' }
        default   { 'White'   }
    }

    Write-Host $Entry -ForegroundColor $Color

    # Grava imediatamente no arquivo (sem buffer) — log em tempo real
    try {
        Add-Content -Path $LogFile -Value $Entry -Encoding UTF8 -ErrorAction Stop
    }
    catch {
        # Falha no log não deve interromper a execução principal
        Write-Host "  [AVISO-INTERNO] Falha ao gravar no log: $_" -ForegroundColor DarkYellow
    }
}

# ==============================================================================
# SEÇÃO 3 — INICIALIZAÇÃO DE DIRETÓRIOS
# ==============================================================================

function Initialize-OutputDirectories {
    <#
    .SYNOPSIS
        Cria os diretórios de saída caso não existam.
    #>
    [CmdletBinding()]
    param()

    foreach ($Dir in @($LogDir, $CSVDir)) {
        if (-not (Test-Path -LiteralPath $Dir -PathType Container)) {
            try {
                New-Item -Path $Dir -ItemType Directory -Force | Out-Null
                # Antes do arquivo de log existir, usa Write-Host diretamente
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
# SEÇÃO 4 — MENU DE SELEÇÃO DO ESCOPO (FLORESTA / DOMÍNIO)
# ==============================================================================

function Show-ScopeMenu {
    <#
    .SYNOPSIS
        Exibe menu interativo para o administrador selecionar o escopo de análise:
        toda a floresta AD, um domínio específico ou apenas o servidor local.
    .OUTPUTS
        [PSCustomObject] com:
          Mode        [string]   — 'Forest' | 'Domain' | 'Local'
          Domains     [string[]] — domínios selecionados (vazio em modo Local)
          LocalServer [string]   — nome do servidor local (preenchido em modo Local)
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

    # Obtém a topologia da floresta via .NET (não depende do módulo AD)
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

    # Loop até receber uma entrada válida
    while ($true) {
        $Raw = Read-Host '  Digite o numero da opcao (ou L para servidor atual)'

        # Opção: Servidor Local
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
# SEÇÃO 5 — VERIFICAÇÃO DA POLÍTICA DE AUDITORIA KERBEROS
# ==============================================================================

function Test-KerberosAuditPolicy {
    <#
    .SYNOPSIS
        Verifica remotamente se as subcategorias de auditoria Kerberos estão ativas
        no Domain Controller informado.

    .DESCRIPTION
        Conecta-se ao DC via Invoke-Command e executa auditpol usando os GUIDs das
        subcategorias (independente de idioma do SO):
          {0CCE9242...} → Kerberos Authentication Service   (evento 4768)
          {0CCE9240...} → Kerberos Service Ticket Operations (evento 4769)

    .PARAMETER DCName
        FQDN ou nome NetBIOS do Domain Controller.

    .OUTPUTS
        [PSCustomObject] com:
          BothEnabled   [bool]   — ambas subcategorias ativas
          AuthEnabled   [bool]   — Kerberos Authentication Service (4768)
          TicketEnabled [bool]   — Kerberos Service Ticket Operations (4769)
          ConnectError  [string] — mensagem de erro de conectividade (se houver)
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory)]
        [string]$DCName
    )

    Write-Log "  Verificando politica de auditoria Kerberos em: $DCName" -Level INFO

    # Detecta se o DC alvo é o servidor local — evita dependência de WinRM
    $IsLocalDC = ($DCName -eq $env:COMPUTERNAME) -or
                 ($DCName -ieq 'localhost') -or
                 ($DCName -eq '127.0.0.1')

    try {
        if ($IsLocalDC) {
            # Execução local: auditpol roda diretamente no processo atual
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

                # Verifica se a subcategoria tem configuração de auditoria ativa.
                # A presença de "Success" ou "Failure" na saída indica que está habilitada.
                # O uso do GUID evita dependência de idioma (PT, EN, ES, etc.).
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
# SEÇÃO 6 — CONVERSÃO DO TIPO DE CRIPTOGRAFIA (STRING → INT)
# ==============================================================================

function ConvertFrom-EncTypeString {
    <#
    .SYNOPSIS
        Converte o valor do campo TicketEncryptionType (pode vir como "0x17" ou "23")
        para um inteiro comparável. Retorna $null se o valor for inválido.
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
        # Formato hexadecimal com prefixo "0x" (ex.: "0x17", "0x01")
        if ($Value -match '^0[xX]([0-9A-Fa-f]+)$') {
            return [Convert]::ToInt32($Matches[1], 16)
        }
        # Formato decimal (ex.: "23", "1", "3")
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
# SEÇÃO 7 — COLETA E FILTRAGEM DE EVENTOS KERBEROS (4768 / 4769)
# ==============================================================================

function Get-WeakEncryptionEvents {
    <#
    .SYNOPSIS
        Coleta eventos 4768 e 4769 do log de Segurança de um Domain Controller
        e retorna apenas os que utilizam criptografia fraca (RC4, DES).

    .DESCRIPTION
        Utiliza Get-WinEvent com filtro XPath para máximo desempenho:
          - O filtro é avaliado no servidor remoto, reduzindo tráfego de rede.
          - Apenas os eventos relevantes (4768/4769 no período) trafegam pela rede.
          - A filtragem por tipo de criptografia fraca é feita localmente após o parse
            do XML de cada evento.

    .PARAMETER DCName
        Nome do Domain Controller.

    .PARAMETER DaysBack
        Janela de tempo retroativa em dias (padrão: 30).

    .OUTPUTS
        [PSObject[]] Lista de eventos filtrados com todos os campos relevantes.
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

    # Converte a data de início para formato UTC ISO 8601 exigido pelo XPath do Event Log
    $StartUTC = (Get-Date).AddDays(-$DaysBack).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.000Z')

    # ── Filtro XPath otimizado ─────────────────────────────────────────────────
    # Filtra no servidor: apenas EventIDs 4768/4769 no período → tráfego mínimo.
    # O operador &gt;= é a codificação XML de >=.
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

    # Detecta se o DC alvo é o servidor local — evita dependência de WinRM
    $IsLocalDC = ($DCName -eq $env:COMPUTERNAME) -or
                 ($DCName -ieq 'localhost') -or
                 ($DCName -eq '127.0.0.1')

    # ── Coleta os eventos brutos via Get-WinEvent ──────────────────────────────
    try {
        if ($IsLocalDC) {
            # Leitura direta do log local — sem tráfego de rede
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
        # Ausência de eventos no período é um cenário normal, não um erro
        if ($_.Exception.Message -match 'No events were found|nenhum evento') {
            Write-Log "  Nenhum evento 4768/4769 em '$DCName' no periodo de $DaysBack dias." -Level INFO
            return $LocalList
        }
        Write-Log "  [ERRO] Falha ao coletar eventos de '$DCName': $_" -Level ERROR
        return $LocalList
    }

    # ── Processa cada evento: parse do XML + filtragem por criptografia fraca ──
    foreach ($Evt in $RawEvents) {
        try {
            # Parse do XML do evento para acesso granular aos campos EventData
            [xml]$EvtXml = $Evt.ToXml()

            # Constrói hashtable { NomeDoCampo → Valor } a partir dos nós Data
            $D = @{}
            foreach ($Node in $EvtXml.Event.EventData.Data) {
                $D[$Node.Name] = $Node.'#text'
            }

            # ── Extrai e converte o tipo de criptografia ──────────────────────
            $EncRaw = if ($D.ContainsKey('TicketEncryptionType')) { $D['TicketEncryptionType'] } else { $null }
            $EncInt = ConvertFrom-EncTypeString -Value $EncRaw

            # Descarta eventos sem tipo de criptografia (ex.: pré-autenticação falhou)
            if ($null -eq $EncInt) { continue }

            # ── Filtra apenas tipos de criptografia FRACA ─────────────────────
            if ($EncInt -notin $WeakEncTypes) { continue }

            $WeakFound++

            # Nome amigável do tipo de criptografia para exibição/exportação
            $EncName = if ($EncTypeMap.ContainsKey($EncInt)) {
                '{0} (0x{1:X2})' -f $EncTypeMap[$EncInt], $EncInt
            }
            else {
                '0x{0:X2} (tipo desconhecido)' -f $EncInt
            }

            # Remove prefixo de IPv4 mapeado em IPv6 (::ffff:192.168.x.x → 192.168.x.x)
            $IP = ([string]($D['IpAddress'])) -replace '^::ffff:', '' -replace '^\s+|\s+$', ''

            # ── Monta o objeto de resultado estruturado ───────────────────────
            # [ordered] garante a ordem dos campos no CSV exportado
            $Obj = [PSCustomObject][ordered]@{
                Timestamp                = $Evt.TimeCreated
                EventID                  = $Evt.Id

                # Conta que solicitou o ticket
                AccountName              = [string]($D['TargetUserName'])
                AccountDomain            = [string]($D['TargetDomainName'])

                # Origem da solicitação (identificação do sistema legado)
                ClientAddress            = $IP
                ClientPort               = [string]($D['IpPort'])

                # ServiceName: relevante apenas em 4769 (TGS). Em 4768 (TGT) é N/A.
                ServiceName              = if ($Evt.Id -eq 4769) {
                                               [string]($D['ServiceName'])
                                           } else {
                                               'N/A (TGT - evento 4768)'
                                           }

                # ─── CAMPO PRINCIPAL: tipo de criptografia fraca detectado ────
                TicketEncryptionType     = $EncName
                EncryptionHex            = '0x{0:X2}' -f $EncInt

                # Status do evento (0x0 = sucesso, outros = erros Kerberos)
                Status                   = [string]($D['Status'])

                # Flag de destaque para identificação rápida de criptografia fraca
                WeakEncryption           = $true

                # DC de origem — essencial para localizar onde os eventos ocorrem
                DomainController         = $DCName
            }

            $LocalList.Add($Obj)
        }
        catch {
            # Falha em um evento individual não interrompe a coleta dos demais
            Write-Log "  [AVISO] Erro ao processar evento RecordId=$($Evt.RecordId): $_" -Level WARNING
            continue
        }
    }

    $LevelResult = if ($WeakFound -gt 0) { 'WARNING' } else { 'SUCCESS' }
    Write-Log "  Resultado '$DCName': $WeakFound evento(s) com cripto fraca de $TotalRaw total." -Level $LevelResult

    return $LocalList
}

# ==============================================================================
# SEÇÃO 8 — FUNÇÃO DE ALERTA: DC SEM AUDITORIA
# ==============================================================================

function Write-AuditAlert {
    <#
    .SYNOPSIS
        Exibe alerta visual destacado no console, grava no log e no arquivo TXT
        quando um DC não possui auditoria Kerberos habilitada.
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

    # Registra no log de execução
    Write-Log "ALERTA: DC '$DCName' (dominio '$DomainName') sem auditoria Kerberos completa. Passando ao proximo DC." -Level WARNING

    # Grava linha estruturada no arquivo TXT de DCs sem auditoria
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
# SEÇÃO 9 — PONTO DE ENTRADA PRINCIPAL
# ==============================================================================

# Cria diretórios antes de qualquer log (Write-Host é usado internamente)
Initialize-OutputDirectories

# ── Cabeçalho do log ──────────────────────────────────────────────────────────
Write-Log ('=' * 72)                                              -Level SECTION
Write-Log "SCRIPT   : $ScriptName"                               -Level SECTION
Write-Log "INICIO   : $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" -Level SECTION
Write-Log "LOG      : $LogFile"                                   -Level SECTION
Write-Log "CSV      : $CSVFile"                                   -Level SECTION
Write-Log "PERIODO  : Ultimos $DaysBack dias"                     -Level SECTION
Write-Log ('=' * 72)                                              -Level SECTION
Write-Log ''                                                      -Level INFO

# ── Verifica e importa o módulo Active Directory ──────────────────────────────
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

# ── Exibe menu e obtém o escopo selecionado pelo administrador ─────────────────
$Scope = Show-ScopeMenu

Write-Log '' -Level INFO
Write-Log "Escopo      : $(if ($Scope.Mode -eq 'Local') { "Servidor Atual ($($Scope.LocalServer))" } else { $Scope.Domains -join ' | ' })" -Level INFO
Write-Log "Cripto alvo : RC4-HMAC (0x17) | DES-CBC-CRC (0x01) | DES-CBC-MD5 (0x03)" -Level INFO
Write-Log '' -Level INFO

# ==============================================================================
# SEÇÃO 10 — LOOP PRINCIPAL: DOMÍNIOS → DCs → AUDITORIA → EVENTOS
# ==============================================================================

if ($Scope.Mode -eq 'Local') {

    # ── Modo: Servidor Atual ───────────────────────────────────────────────────
    $LocalServer = $Scope.LocalServer

    # Obtém o domínio do servidor local para exibição nos alertas
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

    # ETAPA A — Verificação da política de auditoria Kerberos (local)
    $Audit = Test-KerberosAuditPolicy -DCName $LocalServer

    if (-not $Audit.BothEnabled) {
        Write-AuditAlert -DCName $LocalServer -DomainName $LocalDomain -AuditStatus $Audit
        $DCsNoAudit.Add($LocalServer)
    }
    else {
        # ETAPA B — Coleta de eventos 4768/4769 com criptografia fraca (local)
        $Events = Get-WeakEncryptionEvents -DCName $LocalServer -DaysBack $DaysBack
        foreach ($E in $Events) {
            $AllResults.Add($E)
        }
    }

}
else {

    # ── Modo: Floresta ou Domínio específico ──────────────────────────────────
    foreach ($Domain in $Scope.Domains) {

        Write-Log ('=' * 72)         -Level SECTION
        Write-Log "DOMINIO: $Domain" -Level SECTION
        Write-Log ('=' * 72)         -Level SECTION

        # ── Obtém lista de Domain Controllers do domínio ──────────────────────
        try {
            [string[]]$DCs = Get-ADDomainController -Filter * -Server $Domain -ErrorAction Stop |
                             Select-Object -ExpandProperty HostName |
                             Sort-Object

            Write-Log "Domain Controllers encontrados em '$Domain': $($DCs.Count)" -Level INFO
            Write-Log "Lista: $($DCs -join ', ')" -Level INFO
        }
        catch {
            Write-Log "Erro ao listar DCs do dominio '$Domain': $_" -Level ERROR
            continue   # Passa para o próximo domínio
        }

        # ── Processa cada Domain Controller ───────────────────────────────────
        foreach ($DC in $DCs) {

            Write-Log ''            -Level INFO
            Write-Log ('-' * 60)   -Level INFO
            Write-Log "DC: $DC"    -Level INFO
            Write-Log ('-' * 60)   -Level INFO

            # ══════════════════════════════════════════════════════════════════
            # ETAPA A — Verificação da política de auditoria Kerberos
            # ══════════════════════════════════════════════════════════════════
            $Audit = Test-KerberosAuditPolicy -DCName $DC

            if (-not $Audit.BothEnabled) {
                # Alerta, grava no TXT e passa para o próximo DC
                Write-AuditAlert -DCName $DC -DomainName $Domain -AuditStatus $Audit
                $DCsNoAudit.Add($DC)
                continue
            }

            # ══════════════════════════════════════════════════════════════════
            # ETAPA B — Coleta de eventos 4768/4769 com criptografia fraca
            # ══════════════════════════════════════════════════════════════════
            $Events = Get-WeakEncryptionEvents -DCName $DC -DaysBack $DaysBack

            foreach ($E in $Events) {
                $AllResults.Add($E)
            }

        }   # fim foreach DC
    }       # fim foreach Domain

}   # fim if/else escopo

# ==============================================================================
# SEÇÃO 11 — EXPORTAÇÃO DO CSV E RELATÓRIO FINAL
# ==============================================================================

Write-Log ''                    -Level INFO
Write-Log ('=' * 72)            -Level SECTION
Write-Log 'RELATORIO FINAL'     -Level SECTION
Write-Log ('=' * 72)            -Level SECTION

if ($AllResults.Count -gt 0) {

    Write-Log "Total de eventos com CRIPTOGRAFIA FRACA detectados: $($AllResults.Count)" -Level WARNING

    # ── Exporta CSV ────────────────────────────────────────────────────────────
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

    # ── Resumo por tipo de criptografia ───────────────────────────────────────
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

    # ── Resumo por Domain Controller ──────────────────────────────────────────
    Write-Log ''  -Level INFO
    Write-Log '[ RESUMO POR DOMAIN CONTROLLER ]' -Level SECTION
    $AllResults |
        Group-Object DomainController |
        Sort-Object Count -Descending |
        ForEach-Object {
            Write-Log ('  {0,-55} : {1,6} evento(s)' -f $_.Name, $_.Count) -Level INFO
        }

    # ── Top 10 contas com mais eventos de criptografia fraca ──────────────────
    Write-Log ''  -Level INFO
    Write-Log '[ TOP 10 CONTAS — MAIOR VOLUME DE CRIPTO FRACA ]' -Level SECTION
    $AllResults |
        Group-Object AccountName |
        Sort-Object Count -Descending |
        Select-Object -First 10 |
        ForEach-Object {
            Write-Log ('  {0,-55} : {1,6} evento(s)' -f $_.Name, $_.Count) -Level WARNING
        }

    # ── Top 10 IPs de origem (prováveis sistemas legados) ─────────────────────
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

    # ── Prévia no console (primeiros 50 registros) ────────────────────────────
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

# ── Alerta consolidado: DCs sem auditoria ─────────────────────────────────────
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

# ── Rodapé final ──────────────────────────────────────────────────────────────
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
