# Exibindo logo da Empresa
function Show-Logo 
{
    Clear-Host
    Write-Host "========================================================" -ForegroundColor Green
    Write-Host "||                                                                                                                   ||" -ForegroundColor Green
    Write-Host "||                INSTALL TOOLS - SYSTEM MANAGER                                  ||" -ForegroundColor Green
    Write-Host "||                                                                                                                   ||" -ForegroundColor Green
    Write-Host "||                                                                                                                   ||" -ForegroundColor Green
    Write-Host "||                                                                                                                   ||" -ForegroundColor Green
    Write-Host "||                                                                                                                   ||" -ForegroundColor Green
    Write-Host "||  Version: 1.6v                                                                                          ||" -ForegroundColor Green
    Write-Host "||  Owner: Matheus Pellegrini                                                                 ||" -ForegroundColor Green
    Write-Host "||  Contact: matheus_pellegrini@outlook.com                                    ||" -ForegroundColor Green
    Write-Host "========================================================" -ForegroundColor Green

}

Show-Logo

# Verificando se o Powershell esta sendo executado como Administador
$admin = [System.Security.Principal.WindowsPrincipal] [System.Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $admin.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Este script precisa ser executado como administrador!" -ForegroundColor Red
    Pause
    Exit
}

# Função de exibição do menu
function Show-Menu 
{
    Write-Host "1  - Adicionar no Dominio"
    Write-Host "2  - Atualizar Windows"
    Write-Host "3  - Configurar IP Manualmente"
    Write-Host "4  - Instalar Programas Padrões"
    Write-Host "5  - Otimização do Windows"
    Write-Host "6  - Monitoramento do Hardware e Relatorios do Sistema"
    Write-Host "7  - Remover Bloatware do Windows"
    Write-Host "8  - Gerenciamento de Serviços"
    Write-Host "9  - Teste de Conectividade"
    Write-Host "10 - Atualizações de Drive"
    Write-Host "0  - Sair"
}

# Função para paular e limpar tela
function PausarELimpar {
    Write-Host "Pressione qualquer tecla para continuar..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Show-Logo
}

# Função que ira remover o BloatWare
function RemoverBloatware {
    Write-Host "Verificando e removendo aplicativos pré-instalados desnecessarios..." -ForegroundColor Cyan

    # Lista de aplicativos desnecessarios
    $bloatware = @(
        "Microsoft.3DBuilder",
        "Microsoft.BingWeather",
        "Microsoft.GetHelp",
        "Microsoft.GetStarted",
        "Microsoft.MicrosoftSolitaireCollection",
        "Microsoft.People",
        "Microsoft.SkypeApp",
        "Microsoft.Xbox.TCUI",
        "Microsoft.XboxGameOverlay",
        "Microsoft.XboxGamingOverlay",
        "Microsoft.XboxIdentityProvider",
        "Microsoft.XboxSpeechToTextOverlay",
        "Microsoft.YourPhone",
        "Microsoft.ZuneMusic",
        "Microsoft.ZuneVideo",
        "Microsoft.WindowsFeedbackHub",
        "Microsoft.MixedReality.Portal",
        "Microsoft.OneConnect",
        "Microsoft.Messaging"
    )

    # Verificando se alguns desses aplicativos estão instalados
    $instalados = @()
    foreach ($app in $bloatware) {
        $pacote = Get-AppxPackage -Name $app -ErrorAction SilentlyContinue
        if ($pacote) {
            $instalados += $app
        }
    }

    # Se nenhum dos aplicativos estiver instalados, informar o usuario
    if ($instalados.Count -eq 0) {
        Write-Host "Nenhum Bloatware encontrado no sistema, nada para remover!" -ForegroundColor Green
    } else {
        # Remover aplicativos encontados
        foreach ($app in $instalados) {
            Write-Host "Removendo: $app..." -ForegroundColor Yellow
            Get-AppxPackage -Name $app | Remove-AppxPackage
            Start-Sleep -Seconds 1  # Intervalo para evitar conflito
        }
        Write-Host "Remoção Concluida!" -ForegroundColor Green
    }

    PausarELimpar
}


# Função de Gerenciamento de Serviços
function Services {
    Write-Host "1 - Iniciar um Serviço"
    Write-Host "2 - Parar um Serviço"
    Write-Host "3 - Reiniciar um Serviço"
    $escolha = Read-Host "Escolha uma opção: "

    $servico = Read-Host "Digite o nome do serviço"

    switch ($escolha) {
        "1" { Start-Service -Name $servico; Write-Host "$servico Iniciado." }
        "2" { Start-Service -Name $servico; Write-Host "$servico Parado." }
        "3" { Start-Service -Name $servico; Write-Host "$servico Reiniciado." }
        default { Write-Host "Opção Invalida!" }
    }
    PausarELimpar
}

# Funções para adicionar o computador/notebook no dominio
function Add-Domain 
{
    param (
        [string]$dominio = "Dominio",
        [string]$usuarioAdmin = "Usuario Admin",
        [string]$senhaAdmin = "Senha de Admin"
    )

    Write-Host "Iniciando processo para adicionar o computador no dominio..." -ForegroundColor Cyan

    # Verificando se esta rodando como administrador
    $admin = [System.Security.Principal.WindowsPrincipal]::new([System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $admin) {
        Write-Host "Erro: Script precisa ser executado como administrador!" -ForegroundColor Red
        return
    }

    # Convertendo a senha para SecureString
    $secureSenha = ConvertTo-SecureString $senhaAdmin -AsPlainText -Force
    $credenciais = New-Object System.Management.Automation.PSCredential ($usuarioAdmin, $secureSenha)

    # Obtendo nome do computador
    $computador = $env:COMPUTERNAME

    # Verificando se o computador ja esta no dominio
    $infoComputador = Get-WmiObject Win32_ComputerSystem
    if ($infoComputador.PartOfDomain) {
        Write-Host "Computador ja faz parte do dominio: $($infoComputador.Domain)" -ForegroundColor Green
        return
    }

    # Adicionando o computador no dominio
    try {
        Write-Host "Adicionando $computador ao dominio..." -ForegroundColor Yellow
        Add-Computer -DomainName $dominio -Credential $credenciais -Force -ErrorAction Stop
        Write-Host "Computador adicionado com sucesso ao dominio!" -ForegroundColor Green

        # Reiniciando para aplicar as alterações
        Write-Host "Reiniciando o computador em 10 segundos..." -ForegroundColor Cyan
        Start-Sleep -Seconds 10
        Restart-Computer -Force
    } Catch {
        Write-Host "Erro ao adicionar ao dominio..." -ForegroundColor Red
    }
}

# Função de atualização do Windows
function update-Windows {
    Write-Host "Verificando atualizações do Windows..." -ForegroundColor Cyan

    # Verifica se o serviço Windows Update está ativo
    $windowsUpdateService = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
    if ($null -eq $windowsUpdateService -or $windowsUpdateService.Status -ne 'Running') {
        Write-Host "O serviço Windows Update está desativado. Iniciando serviço..." -ForegroundColor Yellow
        Try {
            Start-Service -Name wuauserv -ErrorAction Stop
            Write-Host "Serviço Windows Update iniciado com sucesso!" -ForegroundColor Green
        } Catch {
            Write-Host "Erro ao iniciar o serviço Windows Update. Tente ativá-lo manualmente!" -ForegroundColor Red
            Pause
            return
        }
    }

    # Verifica se o módulo PSWindowsUpdate está instalado
    if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
        Write-Host "O módulo PSWindowsUpdate não está instalado. Instalando..." -ForegroundColor Yellow
        Try {
            Install-Module PSWindowsUpdate -Force -Confirm:$false -ErrorAction Stop
        } Catch {
            Write-Host "Erro ao instalar o módulo PSWindowsUpdate. Verifique sua conexão com a internet!" -ForegroundColor Red
            Pause
            return
        }
    }

    # Importa o módulo PSWindowsUpdate
    Try {
        Import-Module PSWindowsUpdate -ErrorAction Stop
    } Catch {
        Write-Host "Erro ao importar o módulo PSWindowsUpdate. Verifique se ele está instalado corretamente!" -ForegroundColor Red
        Pause
        return
    }

    # Obtém a lista de atualizações disponíveis
    Try {
        $atualizacoes = Get-WindowsUpdate -ErrorAction Stop
    } Catch {
        Write-Host "Erro ao buscar atualizações. Certifique-se de que o Windows Update está ativado!" -ForegroundColor Red
        Pause
        return
    }

    if ($null -eq $atualizacoes -or $atualizacoes.Count -eq 0) {
        Write-Host "O Windows já está atualizado! Nenhuma atualização pendente." -ForegroundColor Green
    } else {
        Write-Host "As seguintes atualizações estão disponíveis:" -ForegroundColor Yellow
        $atualizacoes | ForEach-Object { Write-Host "- $($_.Title)" -ForegroundColor Cyan }

        Write-Host "`nIniciando a instalação das atualizações..." -ForegroundColor Yellow
        Try {
            Install-WindowsUpdate -AcceptAll -AutoReboot -ErrorAction Stop
            Write-Host "Atualizações instaladas com sucesso!" -ForegroundColor Green
        } Catch {
            Write-Host "Erro ao instalar atualizações. Tente novamente mais tarde!" -ForegroundColor Red
        }
    }

    PauseELimpar
}


# Função de instalação dos programas: Google Chrome, FireFox, K-Lite Codecs, WinRAR
function install-Software 
{
    Write-Host "Instalando programas padrões..." -ForegroundColor Cyan

    # Definindo os links de downloadas dos programas
    $programas = @(
        @{ Nome = "Google Chrome"; URL = "https://dl.google.com/chrome/install/latest/chrome_installer.exe"; Caminho = "$env:TEMP\chrome_installer.exe" },
        @{ Nome = "Mozilla Firefox"; URL = "https://download.mozilla.org/?product=firefox-latest&os=win64&lang=pt-BR"; Caminho = "$env:TEMP\firefox_installer.exe" },
        @{ Nome = "K-Lite Codec"; URL = "https://files3.codecguide.com/K-Lite_Codec_Pack_1880_Standard.exe"; Caminho = "$env:TEMP\K-Lite_Codec_Pack_1880_Standard.exe" },
        @{ Nome = "WinRAR"; URL = "https://www.win-rar.com/fileadmin/winrar-versions/winrar-x64-623br.exe"; Caminho = "$env:TEMP\winrar_installer.exe" }
    )

    # Instalar os programas listados acima
    foreach ($app in $programas) {
        if (Test-Path $app.Caminho) {
            Write-Host "$(app.Nome) Já esta instalado. Pulando Instalação..." -ForegroundColor Green
        } else {
            Write-Host "Baixando e instalando $(app.Nome)..." -ForegroundColor Yellow
            Invoke-WebRequest -Uri $app.URL -OutFile $app.Caminho
            Start-Process -FilePath $app.Caminho -ArgumentList "/silent/install" -Wait
            Write-Host "$($app.Nome) Instalado com sucesso!" -ForegroundColor Green
        }
    }
}

# Função para fixar o IP na Placa de Rede
function Config_IP 
{
    param (
        [string]$Interface = "Ethernet", # Nome da interface de rede
        [String]$Mascara = "255.255.255.0",
        [String]$Gateway = "192.168.1.1",
        [String]$DNS1 = "8.8.8.8",
        [String]$DNS2 = "8.8.4.4" 
    )


    Show-Logo
    Write-Host "Configurando o IP fixo..." -ForegroundColor Cyan
    Write-Host ""

    # Solicitando que o usuario coloque o IP desejado
    $IP = Read-Host "Digite qual IP deseja fixar: "

    Write-Host "Configurando o IP fixo na interface: $Interface" -ForegroundColor Cyan

    # Configurando IP, Mascara, Gateway e os DNSs
    try {
        New-NetIPAddress -InterfaceAlias $Interface -IPAddress $IP -PrefixLength 24 -DefaultGateway $Gateway -ErrorAction Stop
        Write-Host "Endereço IP condigurado com sucesso!!" -ForegroundColor Green
    } Catch {
        Write-Host "Erro ao configurar o endereço de IP: $_" -ForegroundColor Red
    }

    # Configurando os servidores de DNS1 e DNS2
    try {
        Set-DnsClientServerAddress -InterfaceAlias $Interface -ServerAddresses ($DNS1, $DNS2)
        Write-Host "Servidores DNS condifurados com sucesso!" -ForegroundColor Green
    } catch {
        Write-Host "Erro ao configurar os servidores DNS: $_" -ForegroundColor Red
    }

    Write-Host "Configuração concluida. Pressione qualquer tecla para continuar..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Show-Logo
}

# Função para realizar a otimização do Windows
function Optimize-Windows
{
    Show-Logo
    Write-Host "Otimizando o Windows..." -ForegroundColor Cyan

    # Perguntando se desejo realizar a desfragmentação de disco
    $desfragmentar = Read-Host "Deseja desfragmentar o disco? [S/N]"
    if ($desfragmentar -match "[Ss]") {
        Write-Host "Desfragmentando o disco..." -ForegroundColor Yellow
        try {
            Optimize-Volume -DriveLetter C -Defrag -ErrorAction Stop
            Write-Host "Desfragmentação Concluida!" -ForegroundColor Green
        } Catch {
            Write-Host "Erro na desfragmentação de disco: $_" -ForegroundColor Red
        }
    }

    # Perguntando se desejo realizar a limpeza de disco
    $limparDisco = Read-Host "Deseja realizar a limpeza de disco? [S/N]"
    if ($limparDisco -match "[Ss]") {
        Write-Host "Executando a limpeza de disco..." -ForegroundColor Yellow
        try {
            Start-Process -FilePath "cleanmgr.exe" -ArgumentList "sagerun:1" -NoNewWindow -Wait
            Write-Host "Limpeza de disco concluida!" -ForegroundColor Green
        } Catch {
            Write-Host "Erro ao executar a limpeza de disco: $_" -ForegroundColor Red
        }
    }

    # Perguntando se desejo Excluir os arquivos temporarios
    $limparTemp = Read-Host "Deseja realizar a exclusão dos arquivos da pasta TEMP? [S/N]"
    if ($limparTemp -match "[Ss]") {
        Write-Host "Realizando a exclusão dos arquivos da pasta temp" -ForegroundColor Yellow
        try {
            Remove-Item -Path "$env:TEMP\*" -Force -Recurse -ErrorAction Stop
            Write-Host "Arquivos temporarios removidos com sucesso!" -ForegroundColor Green
        } Catch {
            Write-Host "Erro ao tentar excluir os arquivos da pasta TEMP: $_" -ForegroundColor Red
        }
    }

    Write-Host "Otimização concluida; Pressione qualquer tecla para continuar..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Show-Logo
}

# Função de monitoramento e Hardware e criação de relatorio do sistema
function Monitor {
    Write-Host "Gerando relatório de monitoramento do sistema..." -ForegroundColor Cyan

    # Caminho do relatório
    $relatorioPath = "$env:TEMP\hardware_report.txt"

    # Obtendo a temperatura da CPU via WMI (caso compatível)
    try {
        $tempCPU = Get-CimInstance -Namespace "root\WMI" -ClassName MSAcpi_ThermalZoneTemperature | 
            Select-Object -ExpandProperty CurrentTemperature
        if ($tempCPU) {
            $tempCPU = ($tempCPU / 10) - 273.15  # Convertendo para Celsius
            $tempCPU = "{0:N1}" -f $tempCPU
        } else {
            $tempCPU = "Não disponível"
        }
    } catch {
        $tempCPU = "Erro ao obter temperatura"
    }

    # Usando Open Hardware Monitor para obter a temperatura da CPU (se disponível)
    try {
        $ohmPath = "C:\Program Files (x86)\OpenHardwareMonitor\OpenHardwareMonitor.exe"
        if (Test-Path $ohmPath) {
            # Inicia o Open Hardware Monitor em segundo plano
            Start-Process -FilePath $ohmPath -ArgumentList "/minimized /nosensors" -WindowStyle Hidden -PassThru | Out-Null

            # Espera um tempo para o Open Hardware Monitor processar
            Start-Sleep -Seconds 2

            # Coleta a saída de temperaturas (toda a informação, mas focando na CPU)
            $ohmOutput = & "$ohmPath" /Report

            # Extrai a temperatura da CPU
            $cpuTempOHM = $ohmOutput | Select-String -Pattern "CPU Package" | ForEach-Object { $_.Line -replace '.*\s(\d+)\s*$', '$1' }
            if ($cpuTempOHM) {
                $tempCPU = $cpuTempOHM
            } else {
                $tempCPU = "Não disponível"
            }
        } else {
            $tempCPU = "Open Hardware Monitor não encontrado"
        }
    } catch {
        $tempCPU = "Erro ao obter temperatura via Open Hardware Monitor"
    }

    # Obtendo o uso da memória RAM
    try {
        $memInfo = Get-CimInstance Win32_OperatingSystem
        $memTotal = $memInfo.TotalVisibleMemorySize / 1MB
        $memLivre = $memInfo.FreePhysicalMemory / 1MB
        $memUsada = $memTotal - $memLivre
        $memUsadaPercent = if ($memTotal -ne 0) { ($memUsada / $memTotal) * 100 } else { 0 }
    } catch {
        $memTotal = 0
        $memUsada = 0
        $memUsadaPercent = "Erro ao obter memória RAM"
    }

    # Obtendo o uso do SSD
    try {
        $disco = Get-PSDrive -Name C -ErrorAction Stop
        $discoTotal = ($disco.Used + $disco.Free) / 1GB
        $discoUsado = $disco.Used / 1GB
        $discoLivre = $disco.Free / 1GB
        $discoUsadoPercent = if ($discoTotal -ne 0) { ($discoUsado / $discoTotal) * 100 } else { 0 }
    } catch {
        $discoTotal = "Erro ao obter informações do disco"
        $discoUsado = "Erro"
        $discoLivre = "Erro"
        $discoUsadoPercent = "Erro"
    }

    # Obtendo a versão do Windows e serial de ativação
    try {
        $winVersao = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ProductName
    } catch {
        $winVersao = "Erro ao obter versão do Windows"
    }

    try {
        $winSerial = (Get-CimInstance SoftwareLicensingService).OA3xOriginalProductKey
        if (-not $winSerial) { $winSerial = "Não encontrado ou OEM" }
    } catch {
        $winSerial = "Erro ao obter serial"
    }

    # Criando relatório formatado
    $relatorio = @"
========================================================
                RELATÓRIO DO SISTEMA
========================================================

🔹 Temperatura da CPU: $tempCPU °C
🔹 Memória RAM usada: {0:N2} GB de {1:N2} GB ({2:N2}%)
🔹 Espaço do SSD (C:): 
   🔸 Usado: {3:N2} GB 
   🔸 Livre: {4:N2} GB 
   🔸 Total: {5:N2} GB 
   🔸 Porcentagem usada: {6:N2}%

=======================================================
                INFORMAÇÕES DO WINDOWS
=======================================================

🔹 Versão do Windows: $winVersao
🔹 Serial do Windows: $winSerial

=======================================================
"@ -f $memUsada, $memTotal, $memUsadaPercent, $discoUsado, $discoLivre, $discoTotal, $discoUsadoPercent

    # Salvando no arquivo
    $relatorio | Out-File -FilePath $relatorioPath -Encoding UTF8
    Write-Host "Relatório gerado em: $relatorioPath" -ForegroundColor Green

    # Exibir relatório no bloco de notas
    Start-Process notepad.exe $relatorioPath

    PausarELimpar
    Show-Logo
}

# Função para teste de Conectividade
function Test-Ping {
    Write-Host "Iniciando o teste de ping..." -ForegroundColor Cyan

    # Solicita o endereço de destino para o teste de ping
    $destino = Read-Host "Digite o endereço IP ou hostname para realizar o teste de ping (ex: google.com)"
    
    # Verifica se o destino não está vazio
    if (-not $destino) {
        Write-Host "Endereço de destino inválido. O teste de ping será cancelado." -ForegroundColor Red
        return
    }

    # Definindo o número de pacotes a serem enviados e o intervalo entre os pings
    $numPings = 10
    $intervalo = 1 # Tempo em segundos entre cada ping
    $pingResults = @()

    Write-Host "Testando a conexão com o destino: $destino..." -ForegroundColor Green

    # Realizando o teste de ping com intervalo entre cada requisição
    for ($i = 1; $i -le $numPings; $i++) {
        $ping = Test-Connection -ComputerName $destino -Count 1 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ResponseTime

        if ($null -ne $ping -and $ping -match '^\d+$') {
            $pingResults += [int]$ping
            Write-Host "Resposta $i : Tempo de ping: $ping ms" -ForegroundColor Green
        } else {
            $pingResults += $null
            Write-Host "Resposta $i : Falha ao alcançar o destino." -ForegroundColor Red
        }

        # Aguarda o intervalo antes do próximo ping
        Start-Sleep $intervalo
    }

    # Filtrando apenas valores numéricos para calcular a média corretamente
    $pingValidos = $pingResults | Where-Object { $_ -ne $null -and $_ -is [int] }

    if ($pingValidos.Count -gt 0) {
        $pingMedio = ($pingValidos | Measure-Object -Average).Average
        $pingMedio = "{0:N2}" -f $pingMedio
    } else {
        $pingMedio = "Não disponível"
    }

    # Calculando a perda de pacotes
    $falhaCount = ($pingResults | Where-Object { $_ -eq $null }).Count
    $sucessoCount = $numPings - $falhaCount
    $perdaPacotes = ($falhaCount / $numPings) * 100

    # Exibindo os resultados finais
    Write-Host "`nResultado do Teste de Ping:" -ForegroundColor Yellow
    Write-Host "-------------------------------"
    Write-Host "Endereço de destino: $destino"
    Write-Host "Total de pacotes enviados: $numPings"
    Write-Host "Pacotes recebidos: $sucessoCount"
    Write-Host "Pacotes perdidos: $falhaCount"
    Write-Host "Tempo médio de resposta: $pingMedio ms"
    Write-Host "Perda de pacotes: {0:N2}%" -f $perdaPacotes

    # Adicionando uma pausa para o usuário ver os resultados
    PausarELimpar
    Show-Logo
}


# Função para verificar as atualizações de Drives
function Driver {
    Write-Host "Verificando atualizações dos drivers no Windows Update..." -ForegroundColor Cyan

    # Verificando se a permissões administrativas
    $admin = [System.Security.Principal.WindowsPrincipal]::new([System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $admin) {
        Write-Host "Erro: Este script precisa ser executado como Administrador!" -ForegroundColor Red
        return
    }

    # Obtendo lista de drivers pendentes de atualização
    Write-Host "Buscando drivers desatualizados, aguarde..." -ForegroundColor Yellow
    $drivers = Get-WindowsUpdate -MicrosoftUpdate -Category 'Drivers' -ErrorAction SilentlyContinue

    if ($drive.Count -eq 0) {
        Write-Host "Nenhuma atualização de drive encontrada..." -ForegroundColor Green
        return
    }

    Write-Host "Drivers encontrados para atualização..." -ForegroundColor Yellow
    $drivers | ForEach-Object {
        Write-Host "🔹 $($_.Title)" -ForegroundColor White
    }

    # Perguntando se o usuario deseja continuar com a instalação
    $confirmacao = Read-Host "Deseja continuar com a instalação? [S/N]"

    if ($confirmacao -match "^[Nn]") {
        Write-Host "Operação cancelada pelo usuario." -ForegroundColor Red
        return
    }

    # Instalando os drivers
    Write-Host "Iniciando a instalação dos drivers..." -ForegroundColor Cyan
    try {
        Install-WindowsUpdate -MicrosoftUpdate -Category 'Drivers' -AcceptAll -AutoReboot | Out-Null
        Write-Host "Atualizações concluidas com sucesso!" -ForegroundColor Green
    } Catch {
        Write-Host "Erro durante a instalação das atualizações: $_" -ForegroundColor Red
    }

    # Exibindo a mensagem final
    Write-Host "Processo finalizado. Verifique se precisa reiniciar o sistema." -ForegroundColor Green

    PausarELimpar
}

# Loop do menu é o usuario digitar a opção de Sair
while ($true) 
{
    Show-Menu
    $opcao = Read-Host "Escolha uma opção: "

    switch ($opcao) {
        "1"  { Add-Domain       }
        "2"  { Update-Windows   }
        "3"  { Config_IP        }
        "4"  { install-Software }
        "5"  { Optimize-Windows }
        "6"  { Monitor          }
        "7"  { RemoverBloatware }
        "8"  { Services         }
        "9"  { Test-Ping        }
        "10" { Driver           }
        "0"  { Write-Host "Saindo..."; exit }
        default { Write-Host "Opção invalida!, Tente novamente." - -ForegroundColor Red}
    }
}