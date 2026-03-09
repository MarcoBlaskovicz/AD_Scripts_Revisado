#Requires -Version 7.1
<#
.SYNOPSIS
    Pesquisa usuários no Microsoft Entra ID com suporte a sessão autenticada persistente.

.DESCRIPTION
    Solicita um ou mais nomes de usuário para pesquisa no Entra ID.
    Verifica se já existe uma sessão ativa antes de solicitar autenticação.
    Exibe informações detalhadas dos usuários encontrados.

.NOTES
    Módulo requerido: Microsoft.Graph
    Instale com: Install-Module Microsoft.Graph -Scope CurrentUser

    Autor  : Marco Farias / NEXA
    Versão : 1.1  — Adicionado: política de expiração de senha e data de expiração calculada
    PS     : 7.1+
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ─────────────────────────────────────────────
# REGIÃO: Helpers de UI
# ─────────────────────────────────────────────
function Write-Header {
    param([string]$Title)
    $line = '─' * 60
    Write-Host "`n$line" -ForegroundColor DarkCyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "$line" -ForegroundColor DarkCyan
}

function Write-Success { param([string]$Msg) Write-Host "  ✔  $Msg" -ForegroundColor Green }
function Write-Info    { param([string]$Msg) Write-Host "  ℹ  $Msg" -ForegroundColor Yellow }
function Write-Fail    { param([string]$Msg) Write-Host "  ✘  $Msg" -ForegroundColor Red }

# ─────────────────────────────────────────────
# REGIÃO: Verificação / instalação do módulo
# ─────────────────────────────────────────────
function Assert-GraphModule {
    Write-Header "Verificando módulo Microsoft.Graph"

    $mod = Get-Module -ListAvailable -Name 'Microsoft.Graph.Users' |
           Sort-Object Version -Descending |
           Select-Object -First 1

    if (-not $mod) {
        Write-Info "Módulo 'Microsoft.Graph' não encontrado. Instalando..."
        try {
            Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber
            Write-Success "Módulo instalado com sucesso."
        }
        catch {
            Write-Fail "Falha ao instalar o módulo: $_"
            exit 1
        }
    }
    else {
        Write-Success "Módulo encontrado: Microsoft.Graph.Users v$($mod.Version)"
    }

    Import-Module Microsoft.Graph.Users -ErrorAction Stop
}

# ─────────────────────────────────────────────
# REGIÃO: Autenticação / verificação de sessão
# ─────────────────────────────────────────────
function Connect-EntraIDSession {
    Write-Header "Verificando autenticação no Entra ID"

    $context = $null
    try { $context = Get-MgContext -ErrorAction SilentlyContinue } catch {}

    if ($context -and $context.Account) {
        Write-Success "Sessão ativa encontrada."
        Write-Info   "Conta   : $($context.Account)"
        Write-Info   "Tenant  : $($context.TenantId)"
        Write-Info   "Escopos : $($context.Scopes -join ', ')"

        $reuse = Read-Host "`n  Usar esta sessão? [S/N] (padrão: S)"
        if ($reuse -match '^[Nn]') {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
            Write-Info "Sessão encerrada. Iniciando nova autenticação..."
            Connect-NewSession
        }
        else {
            Write-Success "Reutilizando sessão existente."
        }
    }
    else {
        Write-Info "Nenhuma sessão ativa. Iniciando autenticação..."
        Connect-NewSession
    }
}

function Connect-NewSession {
    $scopes = @(
        'User.Read.All'
        'Directory.Read.All'
    )

    try {
        Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop
        $ctx = Get-MgContext
        Write-Success "Autenticado como: $($ctx.Account)"
    }
    catch {
        Write-Fail "Falha na autenticação: $_"
        exit 1
    }
}

# ─────────────────────────────────────────────
# REGIÃO: Entrada de usuários
# ─────────────────────────────────────────────
function Get-UserInput {
    Write-Header "Entrada de Usuários para Pesquisa"

    Write-Host @"
  Informe os usuários para pesquisa. Você pode:
    • Digitar um único UPN ou nome de exibição
    • Informar múltiplos separados por vírgula
    • Fornecer o caminho para um arquivo .txt (um usuário por linha)
"@ -ForegroundColor Gray

    $input = Read-Host "`n  Usuário(s) ou caminho do arquivo"
    $input = $input.Trim()

    if ([string]::IsNullOrWhiteSpace($input)) {
        Write-Fail "Nenhuma entrada fornecida."
        exit 1
    }

    # Verifica se é um arquivo
    if (Test-Path -LiteralPath $input -PathType Leaf) {
        $users = Get-Content -Path $input |
                 Where-Object { $_ -match '\S' } |
                 ForEach-Object { $_.Trim() }
        Write-Success "Arquivo carregado: $($users.Count) usuário(s) encontrado(s)."
        return $users
    }

    # Entrada manual — divide por vírgula
    $users = $input -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    return $users
}

# ─────────────────────────────────────────────
# REGIÃO: Pesquisa no Entra ID
# ─────────────────────────────────────────────
function Search-EntraUser {
    param([string]$Query)

    $properties = @(
        'Id', 'DisplayName', 'UserPrincipalName', 'Mail',
        'JobTitle', 'Department', 'OfficeLocation',
        'AccountEnabled', 'CreatedDateTime', 'LastPasswordChangeDateTime',
        'UserType', 'MobilePhone', 'BusinessPhones',
        'OnPremisesSyncEnabled', 'OnPremisesLastSyncDateTime',
        'SignInSessionsValidFromDateTime',
        'PasswordPolicies', 'PasswordProfile'
    )
    $select = $properties -join ','

    # Tenta match exato por UPN primeiro
    try {
        $user = Get-MgUser -UserId $Query -Property $select -ErrorAction Stop
        # Cast explícito para garantir array mesmo com resultado único
        return [array]@($user)
    }
    catch {}

    # Fallback: busca por displayName ou UPN parcial
    $filter = "startsWith(userPrincipalName,'$Query') or startsWith(displayName,'$Query')"
    try {
        # @() + cast [array] garante array mesmo para 0 ou 1 resultado
        [array]$results = @(Get-MgUser -Filter $filter -Property $select -All -ErrorAction Stop)
        return $results
    }
    catch {
        return [array]@()
    }
}

# ─────────────────────────────────────────────
# REGIÃO: Lógica de expiração de senha
# ─────────────────────────────────────────────
function Get-PasswordExpiryInfo {
    <#
    .NOTES
    Lógica:
      • PasswordPolicies contém "DisablePasswordExpiration" → nunca expira
      • PasswordProfile.ForceChangePasswordNextSignIn = true  → troca obrigatória no próximo login
      • Caso contrário: expira conforme a política do tenant (MaxPasswordAge)
        – Obtido via Get-MgDomain; padrão do Entra ID = 90 dias quando não configurado
    #>
    param($User)

    $policies  = $User.PasswordPolicies   # string ou $null
    $profile   = $User.PasswordProfile
    $lastChange = $User.LastPasswordChangeDateTime

    # ── 1. Nunca expira ──────────────────────────────────────
    if ($policies -match 'DisablePasswordExpiration') {
        return [PSCustomObject]@{
            NeverExpires   = $true
            ForceChange    = $false
            ExpiresOn      = $null
            DaysRemaining  = $null
            StatusText     = 'Nunca expira'
            StatusColor    = 'Cyan'
        }
    }

    # ── 2. Troca obrigatória no próximo login ────────────────
    $forceChange = $profile -and $profile.ForceChangePasswordNextSignIn
    if ($forceChange) {
        return [PSCustomObject]@{
            NeverExpires   = $false
            ForceChange    = $true
            ExpiresOn      = $null
            DaysRemaining  = $null
            StatusText     = 'Troca obrigatória no próximo login'
            StatusColor    = 'Yellow'
        }
    }

    # ── 3. Expira — calcular data ────────────────────────────
    # Tenta obter MaxPasswordAge da política do domínio principal
    $maxAgeDays = $null
    try {
        $domain = Get-MgDomain -ErrorAction SilentlyContinue |
                  Where-Object { $_.IsDefault } |
                  Select-Object -First 1

        if ($domain) {
            $pwdPolicy = Get-MgDomainPasswordValidityPeriodInDay `
                            -DomainId $domain.Id -ErrorAction SilentlyContinue
            if ($pwdPolicy -and $pwdPolicy -gt 0) {
                $maxAgeDays = $pwdPolicy
            }
        }
    }
    catch {}

    # Fallback: padrão do Entra ID = 90 dias
    if (-not $maxAgeDays) { $maxAgeDays = 90 }

    if ($lastChange) {
        $expiresOn    = $lastChange.AddDays($maxAgeDays)
        $daysLeft     = [math]::Ceiling(($expiresOn - (Get-Date)).TotalDays)

        if ($daysLeft -lt 0) {
            $statusText  = "EXPIRADA há $([math]::Abs($daysLeft)) dia(s)  [$($expiresOn.ToString('dd/MM/yyyy HH:mm'))]"
            $statusColor = 'Red'
        }
        elseif ($daysLeft -le 14) {
            $statusText  = "Expira em $daysLeft dia(s)  [$($expiresOn.ToString('dd/MM/yyyy HH:mm'))]  ⚠ ATENÇÃO"
            $statusColor = 'Yellow'
        }
        else {
            $statusText  = "Expira em $daysLeft dia(s)  [$($expiresOn.ToString('dd/MM/yyyy HH:mm'))]"
            $statusColor = 'Green'
        }

        return [PSCustomObject]@{
            NeverExpires   = $false
            ForceChange    = $false
            ExpiresOn      = $expiresOn
            DaysRemaining  = $daysLeft
            StatusText     = $statusText
            StatusColor    = $statusColor
        }
    }

    # Sem data de última troca — não é possível calcular
    return [PSCustomObject]@{
        NeverExpires   = $false
        ForceChange    = $false
        ExpiresOn      = $null
        DaysRemaining  = $null
        StatusText     = "Não determinado (política: $maxAgeDays dias / sem data de troca)"
        StatusColor    = 'Gray'
    }
}


function Show-UserResult {
    param($User)

    $statusColor = if ($User.AccountEnabled) { 'Green' } else { 'Red' }
    $statusText  = if ($User.AccountEnabled) { 'Habilitada' } else { 'Desabilitada' }
    $syncText    = if ($User.OnPremisesSyncEnabled) { "Sim (último: $($User.OnPremisesLastSyncDateTime))" } else { 'Não (cloud-only)' }
    $pwdExpiry   = Get-PasswordExpiryInfo -User $User

    Write-Host "`n  ┌─ Usuário Encontrado " -ForegroundColor DarkCyan -NoNewline
    Write-Host ('─' * 38) -ForegroundColor DarkCyan

    $fields = [ordered]@{
        'Nome de Exibição'   = $User.DisplayName
        'UPN'                = $User.UserPrincipalName
        'E-mail'             = $User.Mail
        'Cargo'              = $User.JobTitle
        'Departamento'       = $User.Department
        'Localização'        = $User.OfficeLocation
        'Tipo'               = $User.UserType
        'Conta'              = $statusText
        'Criada em'          = $User.CreatedDateTime
        'Última troca senha' = $User.LastPasswordChangeDateTime
        'Senha expira?'      = $pwdExpiry.StatusText
        'Sincronizado (AD)'  = $syncText
        'Telefone celular'   = $User.MobilePhone
        'Telefone comercial' = ($User.BusinessPhones -join ', ')
        'ID do objeto'       = $User.Id
    }

    foreach ($key in $fields.Keys) {
        $val = $fields[$key]
        if ([string]::IsNullOrWhiteSpace($val)) { $val = '—' }

        Write-Host "  │  " -ForegroundColor DarkCyan -NoNewline
        Write-Host ("{0,-22}" -f $key) -ForegroundColor Gray -NoNewline

        $color = switch ($key) {
            'Conta'         { $statusColor }
            'Senha expira?' { $pwdExpiry.StatusColor }
            default         { 'White' }
        }
        Write-Host $val -ForegroundColor $color
    }

    Write-Host "  └" -ForegroundColor DarkCyan -NoNewline
    Write-Host ('─' * 59) -ForegroundColor DarkCyan
}

# ─────────────────────────────────────────────
# REGIÃO: Exportação opcional
# ─────────────────────────────────────────────
function Export-Results {
    param([System.Collections.Generic.List[object]]$Results)

    if ($Results.Count -eq 0) { return }

    $answer = Read-Host "`n  Exportar resultados para CSV? [S/N] (padrão: N)"
    if ($answer -notmatch '^[Ss]') { return }

    $timestamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
    $defaultPath = Join-Path $env:USERPROFILE "Desktop\EntraID_Usuarios_$timestamp.csv"
    $path = Read-Host "  Caminho do arquivo (Enter para padrão: $defaultPath)"
    if ([string]::IsNullOrWhiteSpace($path)) { $path = $defaultPath }

    try {
        $Results | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        Write-Success "Exportado: $path"
    }
    catch {
        Write-Fail "Erro ao exportar: $_"
    }
}

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
Write-Host "`n  ══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "       Pesquisa de Usuários — Microsoft Entra ID    " -ForegroundColor Cyan
Write-Host "  ══════════════════════════════════════════════════" -ForegroundColor Cyan

Assert-GraphModule
Connect-EntraIDSession

$queries = Get-UserInput

Write-Header "Resultados da Pesquisa"

$allResults = [System.Collections.Generic.List[object]]::new()
$notFound   = [System.Collections.Generic.List[string]]::new()

foreach ($query in $queries) {
    Write-Host "`n  Pesquisando: " -ForegroundColor Gray -NoNewline
    Write-Host $query -ForegroundColor White

    [array]$found = Search-EntraUser -Query $query

    if ($found.Count -eq 0) {
        Write-Fail "Nenhum resultado para: $query"
        $notFound.Add($query)
        continue
    }

    foreach ($u in $found) {
        Show-UserResult -User $u
        $pwdExp = Get-PasswordExpiryInfo -User $u
        $allResults.Add([PSCustomObject]@{
            Pesquisa             = $query
            DisplayName          = $u.DisplayName
            UserPrincipalName    = $u.UserPrincipalName
            Mail                 = $u.Mail
            JobTitle             = $u.JobTitle
            Department           = $u.Department
            OfficeLocation       = $u.OfficeLocation
            UserType             = $u.UserType
            AccountEnabled       = $u.AccountEnabled
            CreatedDateTime      = $u.CreatedDateTime
            LastPasswordChange   = $u.LastPasswordChangeDateTime
            SenhaNuncaExpira     = $pwdExp.NeverExpires
            SenhaExpiraEm        = if ($pwdExp.ExpiresOn) { $pwdExp.ExpiresOn.ToString('dd/MM/yyyy HH:mm') } else { '—' }
            DiasRestantes        = if ($null -ne $pwdExp.DaysRemaining) { $pwdExp.DaysRemaining } else { '—' }
            StatusSenha          = $pwdExp.StatusText
            OnPremisesSync       = $u.OnPremisesSyncEnabled
            MobilePhone          = $u.MobilePhone
            BusinessPhones       = ($u.BusinessPhones -join '; ')
            ObjectId             = $u.Id
        })
    }
}

# Resumo
Write-Header "Resumo"
Write-Success "Usuários encontrados : $($allResults.Count)"
if ($notFound.Count -gt 0) {
    Write-Fail "Não encontrados ($($notFound.Count)): $($notFound -join ', ')"
}

Export-Results -Results $allResults

Write-Host "`n  Concluído.`n" -ForegroundColor Cyan
