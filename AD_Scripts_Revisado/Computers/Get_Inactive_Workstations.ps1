<#
.SYNOPSIS
    Identifica estações de trabalho inativas no Active Directory e, opcionalmente,
    as desabilita e move para uma OU de quarentena.

.DESCRIPTION
    O script varre um domínio AD consultando todos os objetos do tipo "computer"
    que NÃO sejam servidores. Para cada estação encontrada, determina a data do
    último logon usando dois atributos complementares:

      - LastLogonDate        : atributo replicado entre DCs (precisão de 14 dias).
      - LastLogonTimestamp   : valor bruto em formato FileTime, usado como fallback
                               quando LastLogonDate está ausente.

    Computadores cujo último logon seja anterior ao cutoff (hoje - $Days dias), ou
    que nunca tenham feito logon, são classificados como inativos.

    MODO SOMENTE LEITURA (padrão):
      Gera apenas o CSV de inventário com a lista de estações inativas.

    MODO REMEDIAÇÃO (-Remediate):
      Além do inventário, desabilita cada conta inativa e a move para a OU
      informada em -TargetOU. Cada ação é registrada em um CSV de auditoria
      separado. Suporta -WhatIf e -Confirm para simulação segura.

    SAÍDAS GERADAS (em C:\Temp\LogScripts\AD_Workstations_Inativas\<domínio>_<timestamp>\):
      - Execucao_<timestamp>.log                           : log de execução linha a linha.
      - Workstations_Inativas_<domínio>_<dias>dias.csv     : inventário de estações inativas.
      - Workstations_Inativas_Acoes_<timestamp>.csv        : registro de todas as ações de remediação
                                                             (gerado apenas com -Remediate).
      - Workstations_Falhas_Remediacao_<timestamp>.csv     : lista exclusiva de computadores onde
                                                             a desabilitação OU a movimentação falhou.
                                                             Gerado apenas com -Remediate quando há erros.

.PARAMETER Domain
    FQDN do domínio a ser varrido (ex: corp.contoso.com).
    Se omitido, o script solicita interativamente via Read-Host.

.PARAMETER Days
    Número de dias sem logon para considerar uma estação inativa.
    Padrão: 60 dias.

.PARAMETER Remediate
    Switch. Quando presente, desabilita e move cada estação inativa para -TargetOU.
    ATENÇÃO: ação destrutiva. Use -WhatIf para simulação antes de executar em produção.

.PARAMETER TargetOU
    Distinguished Name (DN) da OU de destino para onde as contas inativas serão movidas.
    Obrigatório quando -Remediate é usado. Se omitido, o script solicita interativamente.
    Exemplo: "OU=Inativos,OU=Workstations,DC=corp,DC=contoso,DC=com"

.PARAMETER Root
    Caminho raiz onde as pastas de log/CSV serão criadas.
    Padrão: C:\Temp\LogScripts\AD_Workstations_Inativas

.PARAMETER CsvEncoding
    Encoding dos arquivos CSV gerados. Valores aceitos: utf8, unicode, ascii.
    Padrão: utf8

.EXAMPLE
    .\Verifica_Comp_Inativos_v3.ps1

    Executa interativamente: solicita o domínio via prompt e gera apenas o inventário
    de estações inativas (sem remediação).

.EXAMPLE
    Invoke-InactiveWorkstations -Domain corp.contoso.com -Days 90

    Lista estações sem logon há mais de 90 dias no domínio corp.contoso.com.

.EXAMPLE
    Invoke-InactiveWorkstations -Domain corp.contoso.com -Days 60 -Remediate `
        -TargetOU "OU=Inativos,OU=Workstations,DC=corp,DC=contoso,DC=com" -WhatIf

    Simula a remediação (sem alterar nada no AD). Recomendado antes da execução real.

.EXAMPLE
    Invoke-InactiveWorkstations -Domain corp.contoso.com -Days 60 -Remediate `
        -TargetOU "OU=Inativos,OU=Workstations,DC=corp,DC=contoso,DC=com" -Confirm:$false

    Executa a remediação sem confirmação individual por computador.

.NOTES
    Requisitos:
      - PowerShell 5.1 ou superior
      - Módulo ActiveDirectory (RSAT: AD DS and AD LDS Tools)
      - Permissão de leitura no AD para modo inventário
      - Permissão para desabilitar contas e mover objetos para modo remediação

    Considerações de segurança:
      - O script NÃO exclui contas. Apenas desabilita e move para OU de quarentena.
      - Recomenda-se executar primeiro com -WhatIf para validar o escopo de impacto.
      - O CSV de ações serve como trilha de auditoria de todas as alterações realizadas.
      - Recomenda-se manter os arquivos de log por pelo menos 90 dias para fins de auditoria.

    Limitações conhecidas:
      - LastLogonDate é replicado com latência de até 14 dias entre DCs. Computadores
        com logon recente em outro DC podem aparecer falsamente como inativos.
      - O filtro LDAP exclui objetos com "Server" no atributo operatingSystem, mas
        sistemas com nomes atípicos podem não ser filtrados corretamente.

    Histórico de versões:
      v3.1- 2026-03-03 - Adicionado CSV dedicado de falhas de remediação
                         (Workstations_Falhas_Remediacao_<timestamp>.csv) com contagem
                         no log final, para acesso rápido a computadores onde a
                         desabilitação ou a movimentação para a OU alvo não ocorreu.
      v3  - 2026-03-03 - Correções: [CmdletBinding] reposicionado, proteção contra
                         $null em $computers, $doRemediate como bool local,
                         Read-Host movido para fora do loop, -ResultSetSize $null
                         restaurado, CSV de ações com campos completos, condição
                         de gatilho corrigida para não disparar em dot-source.
      v1  - Versão inicial.

    Autor  : Marco Farias - NEXA

#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ==============================================================================
# FUNÇÕES AUXILIARES
# ==============================================================================

function Initialize-Folders {
<#
.SYNOPSIS
    Cria a estrutura de pastas para armazenar logs e CSVs da execução.
.DESCRIPTION
    Garante que a pasta raiz exista e cria uma subpasta única por execução,
    nomeada com o domínio e o timestamp atual (yyyyMMdd_HHmmss).
    Retorna o caminho completo da subpasta criada.
.PARAMETER Root
    Caminho da pasta raiz. Criada automaticamente se não existir.
.PARAMETER DomainTag
    Identificador do domínio (pontos substituídos por underscores) usado
    para compor o nome da subpasta de execução.
#>
    param(
        [string]$Root = 'C:\Temp\LogScripts\AD_Workstations_Inativas',
        [string]$DomainTag
    )
    if (-not (Test-Path $Root)) { New-Item -Path $Root -ItemType Directory -Force | Out-Null }
    $runTag = "{0}_{1}" -f $DomainTag, (Get-Date -Format 'yyyyMMdd_HHmmss')
    $runDir = Join-Path $Root $runTag
    New-Item -Path $runDir -ItemType Directory -Force | Out-Null
    return $runDir
}

function Write-Log {
<#
.SYNOPSIS
    Grava uma linha de log no console e em arquivo simultaneamente.
.DESCRIPTION
    Formata a mensagem com timestamp e nível (INFO/WARN/ERROR/OK),
    exibe no console via Write-Host e anexa ao arquivo de log da execução.
.PARAMETER Message
    Texto da mensagem a ser registrada.
.PARAMETER LogFile
    Caminho completo do arquivo de log (.log) de destino.
.PARAMETER Level
    Severidade da mensagem. Valores: INFO (padrão), WARN, ERROR, OK.
#>
    param(
        [Parameter(Mandatory)] [string]$Message,
        [Parameter(Mandatory)] [string]$LogFile,
        [ValidateSet('INFO','WARN','ERROR','OK')] [string]$Level = 'INFO'
    )
    $line = "{0} [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Host $line
    Add-Content -Path $LogFile -Value $line
}

function Get-LastLogonDate {
<#
.SYNOPSIS
    Retorna a data do último logon de um objeto computador do AD.
.DESCRIPTION
    Tenta obter a data de último logon usando dois atributos, em ordem de
    preferência:

      1. LastLogonDate  : já convertido para [DateTime], replicado entre DCs
                          (latência de até 14 dias). Usado quando disponível.
      2. LastLogonTimestamp : valor bruto em formato Windows FileTime (Int64).
                              Convertido via [DateTime]::FromFileTime().
                              Usado como fallback quando LastLogonDate está ausente.

    Retorna $null se nenhum dos atributos estiver disponível (computador nunca
    fez logon ou atributos não foram replicados).
.PARAMETER ComputerObj
    Objeto ADComputer retornado por Get-ADComputer com as propriedades
    LastLogonDate e LastLogonTimestamp já carregadas.
#>
    param($ComputerObj)

    # Prioridade 1: LastLogonDate (já é [DateTime], replicado entre DCs)
    if ($ComputerObj.LastLogonDate) { return $ComputerObj.LastLogonDate }

    # Prioridade 2: LastLogonTimestamp (FileTime bruto, não replicado — valor local do DC consultado)
    if ($null -ne $ComputerObj.LastLogonTimestamp -and $ComputerObj.LastLogonTimestamp -ne 0) {
        try { return [DateTime]::FromFileTime([int64]$ComputerObj.LastLogonTimestamp) } catch { return $null }
    }

    # Sem dados de logon disponíveis
    return $null
}

# ==============================================================================
# FUNÇÃO PRINCIPAL
# ==============================================================================

function Invoke-InactiveWorkstations {
<#
.SYNOPSIS
    Varre um domínio AD e identifica/remedia estações de trabalho inativas.
.DESCRIPTION
    Consulta todos os objetos computer do tipo workstation (exclui servidores
    pelo atributo operatingSystem), avalia a data do último logon de cada um
    e classifica como inativo todo computador que não tenha feito logon dentro
    do período definido por -Days. Gera CSV de inventário e, opcionalmente,
    desabilita e move as contas inativas para uma OU de quarentena.
#>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [Parameter(Position=0, Mandatory=$false)] [string]$Domain,
        [int]$Days = 60,
        [switch]$Remediate,
        [string]$TargetOU,
        [string]$Root = 'C:\Temp\LogScripts\AD_Workstations_Inativas',
        [ValidateSet('utf8','unicode','ascii')] [string]$CsvEncoding = 'utf8'
    )

    # ------------------------------------------------------------------
    # PRÉ-REQUISITOS
    # ------------------------------------------------------------------

    # Verifica e importa o módulo ActiveDirectory (exige RSAT instalado)
    if (-not (Get-Module -Name ActiveDirectory)) {
        try { Import-Module ActiveDirectory -ErrorAction Stop } catch { throw "Módulo ActiveDirectory não encontrado." }
    }

    # Solicita o domínio interativamente se não foi passado como parâmetro
    if ([string]::IsNullOrWhiteSpace($Domain)) {
        $Domain = Read-Host 'Informe o domínio (FQDN) para varrer (ex: corp.contoso.com)'
        if ([string]::IsNullOrWhiteSpace($Domain)) { throw 'Domínio não informado.' }
    }

    # ------------------------------------------------------------------
    # INICIALIZAÇÃO DE CAMINHOS E LOGS
    # ------------------------------------------------------------------

    # Data de corte: computadores sem logon desde antes dessa data são inativos
    $cutoff = (Get-Date).AddDays(-$Days)

    # Substitui pontos por underscores para uso seguro em nomes de arquivo/pasta
    $domainTag = ($Domain -replace '\.', '_')

    $runDir       = Initialize-Folders -Root $Root -DomainTag $domainTag
    $runTs        = Get-Date -Format 'yyyyMMdd_HHmmss'
    $logFile      = Join-Path $runDir ("Execucao_{0}.log"                          -f $runTs)
    $csvInventory = Join-Path $runDir ("Workstations_Inativas_{0}_{1}dias.csv"     -f $domainTag, $Days)
    $csvActions   = Join-Path $runDir ("Workstations_Inativas_Acoes_{0}.csv"       -f $runTs)
    $csvFailed    = Join-Path $runDir ("Workstations_Falhas_Remediacao_{0}.csv"    -f $runTs)

    Write-Log -LogFile $logFile -Level INFO -Message "Início | Domínio=$Domain | Dias=$Days | Cutoff=$($cutoff.ToString('yyyy-MM-dd'))"

    # ------------------------------------------------------------------
    # CONEXÃO AO ACTIVE DIRECTORY
    # ------------------------------------------------------------------

    # Descobre automaticamente o DC mais próximo do domínio alvo
    try {
        $dc         = (Get-ADDomainController -Discover -DomainName $Domain).HostName
        $searchBase = (Get-ADDomain -Identity $Domain).DistinguishedName
    } catch {
        Write-Log -LogFile $logFile -Level ERROR -Message "Erro ao conectar no AD: $($_.Exception.Message)"
        throw
    }

    # ------------------------------------------------------------------
    # CONSULTA AO AD
    # ------------------------------------------------------------------

    # Propriedades carregadas por objeto — minimiza tráfego de rede
    $props = @(
        'Name','DNSHostName','OperatingSystem','OperatingSystemVersion',
        'LastLogonTimestamp','LastLogonDate',
        'whenCreated','whenChanged','Enabled',
        'DistinguishedName','CanonicalName','PasswordLastSet'
    )

    # Filtro LDAP: apenas objetos computer que NÃO tenham "Server" no campo operatingSystem
    # Nota: a heurística no loop abaixo complementa esse filtro para casos atípicos
    $ldap = '(&(objectCategory=computer)(!(operatingSystem=*Server*)))'

    Write-Log -LogFile $logFile -Level INFO -Message "Buscando computadores no AD..."

    # @() garante array mesmo que a query retorne zero ou um único objeto
    # -ResultSetSize $null remove o limite padrão e retorna todos os objetos
    $computers = @(Get-ADComputer -Server $dc -SearchBase $searchBase -LDAPFilter $ldap -Properties $props -ResultPageSize 500 -ResultSetSize $null)

    # ------------------------------------------------------------------
    # CONTROLES DE EXECUÇÃO E REMEDIAÇÃO
    # ------------------------------------------------------------------

    $firstInventory = $true; $firstActions = $true; $firstFailed = $true
    $foundWorkstations = 0; $skippedServers = 0; $inactiveCount = 0; $failedCount = 0; $idx = 0
    $total = $computers.Count

    # Usa variável bool local para evitar reatribuição do parâmetro [switch] original
    $doRemediate = $Remediate.IsPresent

    # Solicita a OU destino ANTES do loop para não interromper o processamento a cada iteração
    if ($doRemediate -and [string]::IsNullOrWhiteSpace($TargetOU)) {
        $TargetOU = Read-Host 'Informe a OU destino (DN)'
        if ([string]::IsNullOrWhiteSpace($TargetOU)) {
            Write-Log -LogFile $logFile -Level ERROR -Message 'OU destino vazia. Remediação cancelada.'
            $doRemediate = $false
        }
    }

    # ------------------------------------------------------------------
    # PROCESSAMENTO PRINCIPAL
    # ------------------------------------------------------------------

    foreach ($c in $computers) {
        $idx++
        Write-Log -LogFile $logFile -Level INFO -Message "Processando $idx de $total : $($c.Name)"

        # Segurança adicional: ignora objetos que o filtro LDAP possa não ter excluído
        if ($c.OperatingSystem -and $c.OperatingSystem -match 'Server') { $skippedServers++; continue }

        $foundWorkstations++
        $lastLogon = Get-LastLogonDate -ComputerObj $c

        # Inativo se nunca logou ($null) ou se o último logon foi antes do cutoff
        $isInactive = ($null -eq $lastLogon) -or ($lastLogon -lt $cutoff)

        if ($isInactive) {
            $inactiveCount++

            # Registro de inventário — campos selecionados para o relatório
            $row = [pscustomobject]@{
                Domain               = $Domain
                Name                 = $c.Name
                OperatingSystem      = $c.OperatingSystem
                LastLogonDate        = $lastLogon
                InactiveDaysApprox   = if ($lastLogon) {[int]((New-TimeSpan -Start $lastLogon -End (Get-Date)).TotalDays)} else {$null}
                DistinguishedName    = $c.DistinguishedName
            }

            # Exportação incremental: escreve o cabeçalho apenas na primeira linha,
            # depois apenas os dados para evitar cabeçalhos duplicados no CSV
            $csvText = $row | ConvertTo-Csv -NoTypeInformation
            if ($firstInventory) {
                $csvText | Out-File -FilePath $csvInventory -Encoding $CsvEncoding -Force
                $firstInventory = $false
            } else {
                $csvText | Select-Object -Skip 1 | Out-File -FilePath $csvInventory -Encoding $CsvEncoding -Append
            }

            # ----------------------------------------------------------
            # REMEDIAÇÃO (somente com -Remediate)
            # ----------------------------------------------------------
            # ShouldProcess habilita suporte a -WhatIf e -Confirm nativo do PowerShell
            if ($doRemediate -and $PSCmdlet.ShouldProcess($c.DistinguishedName, "Desabilitar e mover para $TargetOU")) {
                $disabled = $false; $moved = $false; $err = $null

                try {
                    # Passo 1: desabilita a conta no AD
                    Disable-ADAccount -Identity $c.DistinguishedName -Confirm:$false
                    $disabled = $true

                    # Passo 2: move o objeto para a OU de quarentena
                    # O DN original ainda é válido após Disable-ADAccount (apenas a senha/flag muda)
                    Move-ADObject -Identity $c.DistinguishedName -TargetPath $TargetOU -Confirm:$false
                    $moved = $true

                    Write-Log -LogFile $logFile -Level OK -Message "Remediado: $($c.Name)"
                } catch {
                    # Falha parcial: registra o erro mas continua o loop para os demais objetos
                    $err = $_.Exception.Message
                    Write-Log -LogFile $logFile -Level ERROR -Message "Falha: $($c.Name) | $err"
                }

                # Trilha de auditoria: registra o resultado de cada tentativa de remediação
                # Inclui Domain e DistinguishedName para rastreabilidade em ambientes multi-domínio
                $actionObj = [pscustomobject]@{
                    Domain            = $Domain
                    Name              = $c.Name
                    DistinguishedName = $c.DistinguishedName
                    Disabled          = $disabled
                    Moved             = $moved
                    TargetOU          = $TargetOU
                    Error             = $err
                    Timestamp         = (Get-Date)
                }
                $actCsv = $actionObj | ConvertTo-Csv -NoTypeInformation
                if ($firstActions) {
                    $actCsv | Out-File -FilePath $csvActions -Encoding $CsvEncoding -Force; $firstActions = $false
                } else {
                    $actCsv | Select-Object -Skip 1 | Out-File -FilePath $csvActions -Encoding $CsvEncoding -Append
                }

                # CSV de falhas: registra apenas os computadores onde ao menos uma etapa falhou
                if (-not $disabled -or -not $moved) {
                    $failedCount++
                    $failCsv = $actionObj | ConvertTo-Csv -NoTypeInformation
                    if ($firstFailed) {
                        $failCsv | Out-File -FilePath $csvFailed -Encoding $CsvEncoding -Force; $firstFailed = $false
                    } else {
                        $failCsv | Select-Object -Skip 1 | Out-File -FilePath $csvFailed -Encoding $CsvEncoding -Append
                    }
                }
            }
        }
    }

    $summary = "Concluído | Inativas: $inactiveCount de $foundWorkstations workstations analisadas."
    if ($doRemediate) {
        $summary += " | Falhas de remediação: $failedCount"
        if ($failedCount -gt 0) {
            $summary += " | Verifique: $csvFailed"
        }
    }
    Write-Log -LogFile $logFile -Level OK -Message $summary
}

# ==============================================================================
# GATILHO DE EXECUÇÃO DIRETA
# Executa a função principal apenas quando o script é chamado diretamente.
# Quando dot-sourced (. .\script.ps1), apenas carrega as funções sem executar,
# permitindo que o analista chame Invoke-InactiveWorkstations manualmente
# com os parâmetros desejados.
# ==============================================================================
if ($PSCommandPath -and $MyInvocation.InvocationName -ne '.') {
    Invoke-InactiveWorkstations
}
