<#
.SYNOPSIS
    Identifica estações de trabalho inativas no Active Directory e, opcionalmente,
    as desabilita, move para uma OU de quarentena ou desfaz essas ações via rollback.

.DESCRIPTION
    O script varre um domínio AD consultando todos os objetos do tipo "computer"
    que NÃO sejam servidores. Para cada estação encontrada, determina a data do
    último logon usando dois atributos complementares:

      - LastLogonDate        : atributo replicado entre DCs (precisão de 14 dias).
      - LastLogonTimestamp   : valor bruto em formato FileTime, usado como fallback
                               quando LastLogonDate está ausente.

    Computadores cujo último logon seja anterior ao cutoff (hoje - $Days dias), ou
    que nunca tenham feito logon, são classificados como inativos.

    PROTEÇÕES CONTRA INCLUSÃO ACIDENTAL DE SERVIDORES:
      O script aplica três camadas independentes de proteção:
        1. Filtro LDAP  : exclui objetos com "Server" no atributo operatingSystem.
        2. Regex no loop: descarta objetos que escaparam do filtro LDAP mas ainda
                          possuem "Server" no operatingSystem.
        3. -ExcludeServerOU: exclui todos os objetos cujo DN pertença às OUs
                          informadas ou a qualquer sub-OU aninhada, independentemente
                          do valor de operatingSystem (cobre campos vazios/atípicos).

    MODO SOMENTE LEITURA (padrão):
      Gera apenas o CSV de inventário com a lista de estações inativas. Nenhuma
      alteração é feita no AD. O CSV inclui os campos AccountEnabled e
      AlreadyInTargetOU para facilitar a triagem manual do analista.

    MODO REMEDIAÇÃO (-Remediate):
      Além do inventário, desabilita cada conta inativa e a move para a OU
      informada em -TargetOU. Cada ação é registrada em um CSV de auditoria
      separado. Suporta -WhatIf e -Confirm para simulação segura.
      ATENÇÃO: use os campos AccountEnabled=False e AlreadyInTargetOU=True do
      inventário para identificar contas já tratadas antes de executar a remediação.

    MODO ROLLBACK (-Rollback):
      Desfaz uma remediação anterior lendo o CSV de ações gerado por -Remediate
      (informado em -RollbackCsv). Para cada entrada onde Disabled=True:
        - Reabilita a conta (Enable-ADAccount).
        - Tenta mover o objeto de volta para a OU original (extraída do
          DistinguishedName registrado no CSV).
        - Se a OU original não existir mais no AD, reabilita a conta e registra
          um aviso — a conta NÃO é deixada desabilitada por falha de movimentação.
      Apenas entradas onde Disabled=True são processadas (entradas onde a
      desabilitação já havia falhado na remediação são ignoradas).
      Suporta -WhatIf e -Confirm para simulação segura.

    CAMPOS DO CSV DE INVENTÁRIO:
      - Domain             : FQDN do domínio consultado.
      - Name               : nome NetBIOS do computador.
      - OperatingSystem    : sistema operacional registrado no AD.
      - LastLogonDate      : data do último logon identificado (pode ser $null).
      - InactiveDaysApprox : dias aproximados desde o último logon.
      - AccountEnabled     : True se a conta está ativa no AD, False se desabilitada.
      - AlreadyInTargetOU  : True se o objeto já está na -TargetOU ou sub-OU dela;
                             False se está em outra OU; vazio se -TargetOU não foi
                             informada. Útil para identificar contas já quarentenadas.
      - DistinguishedName  : DN completo do objeto no AD.

    INTERPRETAÇÃO COMBINADA DE AccountEnabled + AlreadyInTargetOU:
      False + True  → Já tratado corretamente. Nenhuma ação necessária.
      True  + True  → Na quarentena mas ainda ativo. Revisar manualmente.
      False + False → Desabilitado mas fora da quarentena. Revisar manualmente.
      True  + False → Candidato principal à remediação.

    SAÍDAS GERADAS (em C:\Temp\LogScripts\AD_Workstations_Inativas\<domínio>_<timestamp>\):
      - Execucao_<timestamp>.log                        : log de execução linha a linha.
      - Workstations_Inativas_<domínio>_<dias>dias.csv  : inventário de estações inativas
                                                          com todos os campos descritos acima.
      - Workstations_Inativas_Acoes_<timestamp>.csv     : registro de todas as ações de
                                                          remediação (apenas com -Remediate).
      - Workstations_Falhas_Remediacao_<timestamp>.csv  : computadores onde a desabilitação
                                                          ou movimentação falhou (apenas com
                                                          -Remediate, quando há erros).
      - Workstations_Rollback_Acoes_<timestamp>.csv     : registro de cada ação de rollback
                                                          (apenas com -Rollback).
      - Workstations_Rollback_Falhas_<timestamp>.csv    : computadores onde o rollback falhou
                                                          (apenas com -Rollback, quando há erros).

.PARAMETER Domain
    FQDN do domínio a ser varrido (ex: corp.contoso.com).
    Se omitido, o script solicita interativamente via Read-Host.

.PARAMETER Days
    Número de dias sem logon para considerar uma estação inativa.
    Padrão: 60 dias.

.PARAMETER Remediate
    Switch. Quando presente, desabilita e move cada estação inativa para -TargetOU.
    Não pode ser usado em conjunto com -Rollback.
    ATENÇÃO: ação destrutiva. Use -WhatIf para simulação antes de executar em produção.
    Recomenda-se revisar o CSV de inventário (campos AccountEnabled e AlreadyInTargetOU)
    antes de executar para evitar reprocessar contas já tratadas.

.PARAMETER TargetOU
    Distinguished Name (DN) da OU de destino para onde as contas inativas serão movidas.
    Obrigatório quando -Remediate é usado. Se omitido, o script solicita interativamente.
    Quando informado no modo somente leitura, o campo AlreadyInTargetOU do CSV indica
    quais computadores já estão nessa OU.
    Exemplo: "OU=Inativos,OU=Workstations,DC=corp,DC=contoso,DC=com"

.PARAMETER Rollback
    Switch. Quando presente, desfaz uma remediação anterior lendo o CSV informado em
    -RollbackCsv. Reabilita as contas e tenta movê-las de volta para a OU original.
    Não pode ser usado em conjunto com -Remediate.
    ATENÇÃO: ação destrutiva. Use -WhatIf para simulação antes de executar em produção.
    Observação: o rollback não restaura o estado anterior de Enabled. Contas que já
    estavam desabilitadas antes da remediação serão reabilitadas. Consulte o campo
    AccountEnabled no CSV de inventário gerado antes da remediação para referência.

.PARAMETER RollbackCsv
    Caminho completo do arquivo CSV de ações gerado por uma execução anterior com
    -Remediate (Workstations_Inativas_Acoes_<timestamp>.csv).
    Obrigatório quando -Rollback é usado. Se omitido, o script solicita interativamente.

.PARAMETER ExcludeServerOU
    Lista de Distinguished Names (DNs) de OUs que contêm servidores e devem ser
    completamente ignoradas na busca. Qualquer objeto cujo DistinguishedName contenha
    um dos DNs informados será descartado, incluindo objetos em sub-OUs aninhadas em
    qualquer nível de profundidade. Cada OU é validada no AD antes da query — OUs
    inválidas geram aviso no log e são ignoradas sem abortar a execução.
    Aceita um ou mais valores separados por vírgula. Opcional.
    Exemplo: -ExcludeServerOU "OU=Servers,DC=corp,DC=contoso,DC=com","OU=Infra,DC=corp,DC=contoso,DC=com"

.PARAMETER Root
    Caminho raiz onde as pastas de log/CSV serão criadas. Uma subpasta por execução
    é criada automaticamente com o padrão <domínio>_<timestamp>.
    Padrão: C:\Temp\LogScripts\AD_Workstations_Inativas

.PARAMETER CsvEncoding
    Encoding dos arquivos CSV gerados. Valores aceitos: utf8, unicode, ascii.
    Nota: no PowerShell 5.1, utf8 gera arquivos com BOM. Use unicode se o CSV
    for consumido por ferramentas que não tolerem BOM.
    Padrão: utf8

.EXAMPLE
    .\Verifica_Comp_Inativos_v3.4.ps1

    Executa interativamente: solicita o domínio via prompt e gera apenas o inventário
    de estações inativas (sem remediação). Os campos AccountEnabled e AlreadyInTargetOU
    estarão presentes no CSV para triagem.

.EXAMPLE
    .\Verifica_Comp_Inativos_v3.4.ps1 -Domain corp.contoso.com -Days 90 `
        -TargetOU "OU=Inativos,OU=Workstations,DC=corp,DC=contoso,DC=com" `
        -ExcludeServerOU "OU=Servers,DC=corp,DC=contoso,DC=com"

    Inventário de estações inativas há mais de 90 dias, com AlreadyInTargetOU
    preenchido e OUs de servidores excluídas da busca.

.EXAMPLE
    .\Verifica_Comp_Inativos_v3.4.ps1 -Domain corp.contoso.com -Days 60 -Remediate `
        -TargetOU "OU=Inativos,OU=Workstations,DC=corp,DC=contoso,DC=com" `
        -ExcludeServerOU "OU=Servers,DC=corp,DC=contoso,DC=com" -WhatIf

    Simula a remediação excluindo a OU de servidores (sem alterar nada no AD).
    Recomendado antes da execução real.

.EXAMPLE
    .\Verifica_Comp_Inativos_v3.4.ps1 -Domain corp.contoso.com -Days 60 -Remediate `
        -TargetOU "OU=Inativos,OU=Workstations,DC=corp,DC=contoso,DC=com" `
        -ExcludeServerOU "OU=Servers,DC=corp,DC=contoso,DC=com" -Confirm:$false

    Executa a remediação sem confirmação individual por computador.

.EXAMPLE
    .\Verifica_Comp_Inativos_v3.4.ps1 -Domain corp.contoso.com -Rollback `
        -RollbackCsv "C:\Temp\LogScripts\AD_Workstations_Inativas\corp_contoso_com_20260305_143000\Workstations_Inativas_Acoes_20260305_143000.csv" -WhatIf

    Simula o rollback da remediação (sem alterar nada no AD).
    Recomendado antes da execução real.

.EXAMPLE
    .\Verifica_Comp_Inativos_v3.4.ps1 -Domain corp.contoso.com -Rollback `
        -RollbackCsv "C:\Temp\...\Workstations_Inativas_Acoes_20260305_143000.csv" -Confirm:$false

    Executa o rollback sem confirmação individual por computador.

.NOTES
    Requisitos:
      - PowerShell 5.1 ou superior
      - Módulo ActiveDirectory (RSAT: AD DS and AD LDS Tools)
      - Permissão de leitura no AD para modo inventário
      - Permissão para desabilitar contas e mover objetos para modo remediação/rollback

    Fluxo recomendado de uso:
      1. Executar em modo somente leitura com -TargetOU e -ExcludeServerOU para
         gerar o inventário completo com todos os campos de triagem.
      2. Revisar o CSV — filtrar por AccountEnabled=True e AlreadyInTargetOU=False
         para identificar os candidatos reais à remediação.
      3. Executar com -Remediate -WhatIf para simular o escopo de impacto.
      4. Executar com -Remediate -Confirm:$false para aplicar as alterações.
      5. Em caso de necessidade, executar com -Rollback apontando para o CSV de ações.

    Considerações de segurança:
      - O script NÃO exclui contas. Apenas desabilita e move para OU de quarentena.
      - O CSV de ações serve como trilha de auditoria de todas as alterações realizadas.
      - Recomenda-se manter os arquivos de log por pelo menos 90 dias para auditoria.
      - O rollback processa apenas contas efetivamente desabilitadas (Disabled=True).
      - Se a OU original não existir mais no rollback, a conta é reabilitada mas não
        movida. O analista deve relocar manualmente os objetos indicados no CSV.

    Limitações conhecidas:
      - LastLogonDate é replicado com latência de até 14 dias entre DCs. Computadores
        com logon recente em outro DC podem aparecer falsamente como inativos.
      - O filtro LDAP e a camada de regex excluem objetos com "Server" no atributo
        operatingSystem, mas sistemas com nomes atípicos ou campo vazio podem não ser
        filtrados — use -ExcludeServerOU para cobrir esses casos.
      - O rollback não restaura o estado anterior de Enabled da conta. Contas já
        desabilitadas antes da remediação serão reabilitadas. Consulte o campo
        AccountEnabled no CSV de inventário gerado antes da remediação.

    Histórico de versões:
      v3.4f- 2026-03-05 - Documentação completamente revisada: descrição das três
                          camadas de proteção contra servidores, tabela de campos do
                          CSV de inventário, matriz de interpretação AccountEnabled +
                          AlreadyInTargetOU, fluxo recomendado de uso em 5 passos,
                          exemplos atualizados para uso via linha de comando.
      v3.4e- 2026-03-05 - Adicionados campos AccountEnabled e AlreadyInTargetOU no
                          CSV de inventário. AccountEnabled reflete o atributo Enabled
                          do AD. AlreadyInTargetOU indica se o objeto já está na
                          -TargetOU ou em sub-OU dela (null se -TargetOU não informada).
      v3.4d- 2026-03-05 - Bugfix: bloco param no escopo raiz do script e splatting
                          @PSBoundParameters no gatilho de execução direta. Corrige
                          a causa raiz pela qual nenhum parâmetro da linha de comando
                          era repassado para Invoke-InactiveWorkstations.
      v3.4c- 2026-03-05 - Bugfix: filtro de ExcludeServerOU corrigido de EndsWith
                          para Contains, garantindo exclusão de objetos em sub-OUs
                          aninhadas em qualquer nível de profundidade.
      v3.4b- 2026-03-05 - Bugfix: $dc convertido explicitamente para [string] para
                          evitar erro de binding com ADPropertyValueCollection ao
                          passar o hostname para o parâmetro -Server dos cmdlets AD.
      v3.4a- 2026-03-05 - Adicionado parâmetro -ExcludeServerOU ([string[]]): aceita
                          uma ou mais OUs cujos objetos (e de todas as sub-OUs) são
                          excluídos da busca pelo DN. Cada OU é validada no AD antes
                          da query. Terceira camada de proteção contra servidores,
                          complementar ao filtro LDAP e à verificação por regex de SO.
      v3.3 - 2026-03-05 - Adicionado modo rollback (-Rollback / -RollbackCsv):
                          reabilita contas e restaura OU original com base no CSV de
                          auditoria gerado pelo -Remediate. Se a OU original não existir
                          mais, reabilita a conta e registra aviso. Suporte a -WhatIf
                          e -Confirm. CSVs de auditoria e falhas de rollback separados.
      v3.2 - 2026-03-05 - Adicionada validação da OU destino antes do loop principal.
                          Impede falhas parciais (conta desabilitada mas não movida)
                          causadas por OU inválida ou inacessível.
      v3.1 - 2026-03-03 - Adicionado CSV dedicado de falhas de remediação
                          (Workstations_Falhas_Remediacao_<timestamp>.csv) com contagem
                          no log final, para acesso rápido a computadores onde a
                          desabilitação ou a movimentação para a OU alvo não ocorreu.
      v3   - 2026-03-03 - Correções: [CmdletBinding] reposicionado, proteção contra
                          $null em $computers, $doRemediate como bool local,
                          Read-Host movido para fora do loop, -ResultSetSize $null
                          restaurado, CSV de ações com campos completos, condição
                          de gatilho corrigida para não disparar em dot-source.
      v1   - Versão inicial.

    Autor  : Marco Farias - NEXA

#>

# Bloco param no escopo do script: necessário para que o PowerShell reconheça
# os argumentos da linha de comando e os disponibilize em $PSBoundParameters,
# permitindo o repasse automático para Invoke-InactiveWorkstations via splatting.
[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [Parameter(Position=0, Mandatory=$false)] [string]$Domain,
    [int]$Days = 60,
    [switch]$Remediate,
    [string]$TargetOU,
    [switch]$Rollback,
    [string]$RollbackCsv,
    [string[]]$ExcludeServerOU = @(),
    [string]$Root = 'C:\Temp\LogScripts\AD_Workstations_Inativas',
    [ValidateSet('utf8','unicode','ascii')] [string]$CsvEncoding = 'utf8'
)

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
# FUNÇÃO DE ROLLBACK
# ==============================================================================

function Invoke-Rollback {
<#
.SYNOPSIS
    Desfaz uma remediação anterior lendo o CSV de ações gerado por -Remediate.
.DESCRIPTION
    Para cada linha do CSV onde Disabled=True:
      1. Reabilita a conta no AD (Enable-ADAccount).
      2. Extrai a OU original do DistinguishedName registrado no CSV (remove o
         componente CN= inicial para obter o caminho da OU pai).
      3. Verifica se a OU original ainda existe. Se sim, move o objeto de volta.
         Se não, mantém a conta reabilitada e registra aviso — a conta NÃO é
         deixada desabilitada por falha de movimentação.
    Linhas onde Disabled=False são ignoradas (a desabilitação já havia falhado
    na remediação original, portanto não há o que desfazer).
    Suporta -WhatIf e -Confirm nativamente via CmdletBinding.
.PARAMETER CsvPath
    Caminho do CSV de ações gerado por uma execução anterior com -Remediate.
.PARAMETER Dc
    Hostname do DC a ser usado nas operações de AD.
.PARAMETER LogFile
    Caminho do arquivo de log desta execução de rollback.
.PARAMETER CsvRollbackActions
    Caminho do CSV de auditoria das ações de rollback.
.PARAMETER CsvRollbackFailed
    Caminho do CSV exclusivo de falhas de rollback.
.PARAMETER CsvEncoding
    Encoding para escrita dos CSVs de saída.
.PARAMETER PSCmdlet
    Objeto PSCmdlet da função chamadora, necessário para propagar ShouldProcess.
#>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [Parameter(Mandatory)] [string]$CsvPath,
        [Parameter(Mandatory)] [string]$Dc,
        [Parameter(Mandatory)] [string]$LogFile,
        [Parameter(Mandatory)] [string]$CsvRollbackActions,
        [Parameter(Mandatory)] [string]$CsvRollbackFailed,
        [Parameter(Mandatory)] [string]$CsvEncoding,
        [Parameter(Mandatory)] $CallerCmdlet
    )

    # Carrega o CSV de ações da remediação original
    $actions = @(Import-Csv -Path $CsvPath -Encoding $CsvEncoding)
    $total   = $actions.Count
    Write-Log -LogFile $LogFile -Level INFO -Message "Rollback | $total entradas lidas de: $CsvPath"

    # Filtra apenas entradas onde a desabilitação foi efetivamente realizada
    $toProcess = @($actions | Where-Object { $_.Disabled -eq 'True' })
    $skipped   = $total - $toProcess.Count
    Write-Log -LogFile $LogFile -Level INFO -Message "Rollback | $($toProcess.Count) contas a reabilitar | $skipped ignoradas (Disabled=False)"

    $firstRbActions = $true; $firstRbFailed = $true
    $idx = 0; $successCount = 0; $failedCount = 0

    foreach ($entry in $toProcess) {
        $idx++
        $dn   = $entry.DistinguishedName
        $name = $entry.Name
        Write-Log -LogFile $LogFile -Level INFO -Message "Rollback $idx de $($toProcess.Count) : $name"

        # Extrai a OU original: remove o primeiro componente (CN=<nome>,) do DN original.
        # Exemplo: "CN=PC01,OU=TI,DC=corp,DC=com" -> "OU=TI,DC=corp,DC=com"
        $originalOU = $dn -replace '^CN=[^,]+,', ''

        if (-not $CallerCmdlet.ShouldProcess($dn, "Reabilitar e mover de volta para $originalOU")) { continue }

        $reenabled   = $false
        $movedBack   = $false
        $ouMissing   = $false
        $err         = $null

        # O objeto foi movido para a OU de quarentena; seu DN atual usa o mesmo CN
        # mas com o path da TargetOU registrada no CSV
        $currentDN = "CN=$name,$($entry.TargetOU)"

        try {
            # Passo 1: reabilita a conta usando o DN atual (na OU de quarentena)
            Enable-ADAccount -Identity $currentDN -Confirm:$false
            $reenabled = $true
            Write-Log -LogFile $LogFile -Level OK -Message "Reabilitado: $name"
        } catch {
            $err = $_.Exception.Message
            Write-Log -LogFile $LogFile -Level ERROR -Message "Falha ao reabilitar $name | $err"
        }

        # Passo 2: tenta mover de volta para a OU original (somente se reabilitou com sucesso)
        if ($reenabled) {
            try {
                Get-ADOrganizationalUnit -Identity $originalOU -Server $Dc -ErrorAction Stop | Out-Null
            } catch {
                # OU original não existe mais — registra aviso mas mantém conta ativa
                $ouMissing = $true
                Write-Log -LogFile $LogFile -Level WARN -Message "OU original não encontrada para $name ($originalOU). Conta reabilitada mas não movida. Realocação manual necessária."
            }

            if (-not $ouMissing) {
                try {
                    Move-ADObject -Identity $currentDN -TargetPath $originalOU -Confirm:$false
                    $movedBack = $true
                    Write-Log -LogFile $LogFile -Level OK -Message "Movido de volta: $name -> $originalOU"
                } catch {
                    $err = $_.Exception.Message
                    Write-Log -LogFile $LogFile -Level ERROR -Message "Falha ao mover $name de volta | $err"
                }
            }
        }

        # Determina resultado consolidado
        $rollbackOk = $reenabled -and ($movedBack -or $ouMissing)
        if ($rollbackOk) { $successCount++ } else { $failedCount++ }

        # Auditoria de rollback
        $rbObj = [pscustomobject]@{
            Domain            = $entry.Domain
            Name              = $name
            DistinguishedName = $dn
            OriginalOU        = $originalOU
            Reenabled         = $reenabled
            MovedBack         = $movedBack
            OUMissing         = $ouMissing
            Error             = $err
            Timestamp         = (Get-Date)
        }
        $rbCsv = $rbObj | ConvertTo-Csv -NoTypeInformation
        if ($firstRbActions) {
            $rbCsv | Out-File -FilePath $CsvRollbackActions -Encoding $CsvEncoding -Force
            $firstRbActions = $false
        } else {
            $rbCsv | Select-Object -Skip 1 | Out-File -FilePath $CsvRollbackActions -Encoding $CsvEncoding -Append
        }

        # CSV de falhas: somente quando reabilitação falhou (OU ausente não é falha)
        if (-not $reenabled) {
            $failCsv = $rbObj | ConvertTo-Csv -NoTypeInformation
            if ($firstRbFailed) {
                $failCsv | Out-File -FilePath $CsvRollbackFailed -Encoding $CsvEncoding -Force
                $firstRbFailed = $false
            } else {
                $failCsv | Select-Object -Skip 1 | Out-File -FilePath $CsvRollbackFailed -Encoding $CsvEncoding -Append
            }
        }
    }

    $summary = "Rollback concluído | Sucesso: $successCount | Falhas: $failedCount | Ignorados: $skipped"
    if ($failedCount -gt 0) { $summary += " | Verifique: $CsvRollbackFailed" }
    Write-Log -LogFile $LogFile -Level OK -Message $summary
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
        [switch]$Rollback,
        [string]$RollbackCsv,
        [string[]]$ExcludeServerOU = @(),
        [string]$Root = 'C:\Temp\LogScripts\AD_Workstations_Inativas',
        [ValidateSet('utf8','unicode','ascii')] [string]$CsvEncoding = 'utf8'
    )

    # ------------------------------------------------------------------
    # PRÉ-REQUISITOS
    # ------------------------------------------------------------------

    # -Remediate e -Rollback são mutuamente exclusivos
    if ($Remediate -and $Rollback) {
        throw '-Remediate e -Rollback não podem ser usados simultaneamente.'
    }

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

    $runDir              = Initialize-Folders -Root $Root -DomainTag $domainTag
    $runTs               = Get-Date -Format 'yyyyMMdd_HHmmss'
    $logFile             = Join-Path $runDir ("Execucao_{0}.log"                          -f $runTs)
    $csvInventory        = Join-Path $runDir ("Workstations_Inativas_{0}_{1}dias.csv"     -f $domainTag, $Days)
    $csvActions          = Join-Path $runDir ("Workstations_Inativas_Acoes_{0}.csv"       -f $runTs)
    $csvFailed           = Join-Path $runDir ("Workstations_Falhas_Remediacao_{0}.csv"    -f $runTs)
    $csvRollbackActions  = Join-Path $runDir ("Workstations_Rollback_Acoes_{0}.csv"       -f $runTs)
    $csvRollbackFailed   = Join-Path $runDir ("Workstations_Rollback_Falhas_{0}.csv"      -f $runTs)

    Write-Log -LogFile $logFile -Level INFO -Message "Início | Domínio=$Domain | Dias=$Days | Cutoff=$($cutoff.ToString('yyyy-MM-dd')) | OUs excluídas=$($ExcludeServerOU.Count)"

    # ------------------------------------------------------------------
    # CONEXÃO AO ACTIVE DIRECTORY
    # ------------------------------------------------------------------

    # Descobre automaticamente o DC mais próximo do domínio alvo
    try {
        # HostName retorna ADPropertyValueCollection — [string] força conversão segura para string
        $dc         = [string](Get-ADDomainController -Discover -DomainName $Domain).HostName
        $searchBase = (Get-ADDomain -Identity $Domain).DistinguishedName
    } catch {
        Write-Log -LogFile $logFile -Level ERROR -Message "Erro ao conectar no AD: $($_.Exception.Message)"
        throw
    }

    # ------------------------------------------------------------------
    # VALIDAÇÃO E NORMALIZAÇÃO DAS OUs EXCLUÍDAS
    # ------------------------------------------------------------------

    # Normaliza cada DN para letras minúsculas para comparação case-insensitive.
    # Valida a existência de cada OU no AD — OUs inválidas geram WARN e são ignoradas
    # (não abortam a execução, pois são proteção adicional, não bloqueio obrigatório).
    $excludedOUNorm = [System.Collections.Generic.List[string]]::new()
    foreach ($ouDN in $ExcludeServerOU) {
        if ([string]::IsNullOrWhiteSpace($ouDN)) { continue }
        try {
            Get-ADOrganizationalUnit -Identity $ouDN -Server $dc -ErrorAction Stop | Out-Null
            $excludedOUNorm.Add($ouDN.ToLower())
            Write-Log -LogFile $logFile -Level INFO -Message "OU excluída validada: $ouDN"
        } catch {
            Write-Log -LogFile $logFile -Level WARN -Message "OU excluída não encontrada no AD (será ignorada): $ouDN | $($_.Exception.Message)"
        }
    }

    # ------------------------------------------------------------------
    # MODO ROLLBACK — executa e encerra sem consultar o AD
    # ------------------------------------------------------------------

    if ($Rollback) {
        # Solicita o CSV interativamente se não foi passado como parâmetro
        if ([string]::IsNullOrWhiteSpace($RollbackCsv)) {
            $RollbackCsv = Read-Host 'Informe o caminho do CSV de ações da remediação (Workstations_Inativas_Acoes_*.csv)'
        }
        if ([string]::IsNullOrWhiteSpace($RollbackCsv)) {
            Write-Log -LogFile $logFile -Level ERROR -Message 'Caminho do CSV de rollback não informado. Operação cancelada.'
            return
        }
        if (-not (Test-Path $RollbackCsv)) {
            Write-Log -LogFile $logFile -Level ERROR -Message "CSV de rollback não encontrado: $RollbackCsv"
            return
        }

        Write-Log -LogFile $logFile -Level INFO -Message "Início do rollback | CSV=$RollbackCsv"

        Invoke-Rollback `
            -CsvPath            $RollbackCsv `
            -Dc                 ($dc | Select-Object -First 1) `
            -LogFile            $logFile `
            -CsvRollbackActions $csvRollbackActions `
            -CsvRollbackFailed  $csvRollbackFailed `
            -CsvEncoding        $CsvEncoding `
            -CallerCmdlet       $PSCmdlet

        return
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

    Write-Log -LogFile $logFile -Level INFO -Message "$($computers.Count) objetos retornados pelo AD antes dos filtros de exclusão."

    # Filtra objetos cujo DN esteja contido em qualquer OU excluída (ou suas sub-OUs).
    # Usa .Contains() para cobrir sub-OUs aninhadas em qualquer nível:
    #   DN "CN=SRV01,OU=SQL,OU=Servers,DC=corp,DC=com" contém "ou=servers,dc=corp,dc=com"
    #   DN "CN=SRV02,OU=Servers,DC=corp,DC=com"        contém "ou=servers,dc=corp,dc=com"
    # A vírgula prefixada garante que não haja falso positivo por nome parcial de OU:
    #   "ou=servers2,..." não seria bloqueado por uma exclusão de "ou=servers,..."
    if ($excludedOUNorm.Count -gt 0) {
        $beforeFilter = $computers.Count
        $computers = @($computers | Where-Object {
            $dnLower = $_.DistinguishedName.ToLower()
            $blocked = $false
            foreach ($ouNorm in $excludedOUNorm) {
                if ($dnLower.Contains(",$ouNorm")) {
                    $blocked = $true; break
                }
            }
            -not $blocked
        })
        $filteredByOU = $beforeFilter - $computers.Count
        Write-Log -LogFile $logFile -Level INFO -Message "$filteredByOU objeto(s) excluídos por -ExcludeServerOU. Restam $($computers.Count) para análise."
    }

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

    # Valida se a OU destino existe no AD antes de iniciar o loop.
    # Evita que uma OU inválida só seja descoberta na primeira tentativa de Move-ADObject,
    # o que resultaria em uma falha parcial (conta desabilitada mas não movida) para cada objeto.
    if ($doRemediate) {
        try {
            Get-ADOrganizationalUnit -Identity $TargetOU -Server $dc -ErrorAction Stop | Out-Null
            Write-Log -LogFile $logFile -Level INFO -Message "OU destino validada: $TargetOU"
        } catch {
            Write-Log -LogFile $logFile -Level ERROR -Message "OU destino inválida ou inacessível: $TargetOU | $($_.Exception.Message)"
            Write-Log -LogFile $logFile -Level ERROR -Message 'Remediação cancelada. Nenhuma alteração foi realizada no AD.'
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
                AccountEnabled       = $c.Enabled
                AlreadyInTargetOU    = if ([string]::IsNullOrWhiteSpace($TargetOU)) { $null } else { $c.DistinguishedName.ToLower().Contains(",$($TargetOU.ToLower())") }
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
# $PSBoundParameters repassa automaticamente todos os parâmetros recebidos
# na linha de comando para a função, sem precisar listá-los manualmente.
# ==============================================================================
if ($PSCommandPath -and $MyInvocation.InvocationName -ne '.') {
    Invoke-InactiveWorkstations @PSBoundParameters
}
