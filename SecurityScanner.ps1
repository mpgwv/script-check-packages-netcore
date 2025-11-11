# SecurityScanner.ps1
param(
    [string]$ProjectPath = ".",
    [switch]$DeepScan = $false,
    [switch]$CheckDependencies = $true,
    [string]$OutputFile = "security_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
)

Write-Host "=== SCANNER DE SEGURANÇA .NET CORE ===" -ForegroundColor Green
Write-Host "Iniciando varredura em: $ProjectPath" -ForegroundColor Yellow

function Write-Report {
    param([string]$Message, [string]$Type = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Type] $Message"
    
    Add-Content -Path $OutputFile -Value $logEntry
    
    switch($Type) {
        "CRITICAL" { Write-Host $logEntry -ForegroundColor Red }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "INFO" { Write-Host $logEntry -ForegroundColor White }
        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
    }
}

function Test-DotNetInstallation {
    try {
        $dotnetVersion = dotnet --version
        Write-Report "SDK .NET detectado: $dotnetVersion" "SUCCESS"
        return $true
    }
    catch {
        Write-Report "SDK .NET não encontrado!" "CRITICAL"
        return $false
    }
}

function Get-ProjectFiles {
    param([string]$Path)
    
    $csprojFiles = Get-ChildItem -Path $Path -Recurse -Filter "*.csproj"
    $slnFiles = Get-ChildItem -Path $Path -Recurse -Filter "*.sln"
    
    return @{
        CsProjFiles = $csprojFiles
        SolutionFiles = $slnFiles
    }
}

function Analyze-Dependencies {
    param([string]$ProjectFile)
    
    Write-Report "Analisando dependências: $($ProjectFile.Name)" "INFO"
    
    try {
        # Restaura pacotes para gerar arquivos de lock
        Write-Report "Restaurando pacotes..." "INFO"
        & dotnet restore $ProjectFile.FullName --force | Out-Null
        
        # Analisa dependências vulneráveis
        Write-Report "Verificando vulnerabilidades conhecidas..." "INFO"
        $vulnerabilityReport = & dotnet list $ProjectFile.FullName package --vulnerable --include-transitive
        
        if ($vulnerabilityReport -match "vulnerável") {
            Write-Report "VULNERABILIDADES ENCONTRADAS!" "CRITICAL"
            $vulnerabilityReport | ForEach-Object {
                if ($_ -match "vulnerável") {
                    Write-Report "Vulnerabilidade: $_" "CRITICAL"
                }
            }
        }
        
        # Verifica pacotes desatualizados
        Write-Report "Verificando pacotes desatualizados..." "INFO"
        $outdatedReport = & dotnet list $ProjectFile.FullName package --outdated
        
        $outdatedReport | ForEach-Object {
            if ($_ -match ">") {
                Write-Report "Pacote desatualizado: $_" "WARNING"
            }
        }
        
        return $vulnerabilityReport, $outdatedReport
    }
    catch {
        Write-Report "Erro ao analisar dependências: $($_.Exception.Message)" "CRITICAL"
    }
}

function Check-SuspiciousFiles {
    param([string]$Path)
    
    Write-Report "Procurando por arquivos suspeitos..." "INFO"
    
    $suspiciousPatterns = @(
        "*.dll", "*.exe", "*.bat", "*.ps1", "*.vbs", "*.js", "*.zip", "*.rar"
    )
    
    $suspiciousExtensions = @(
        ".dll", ".exe", ".bat", ".ps1", ".vbs", ".js", ".zip", ".rar"
    )
    
    $suspiciousKeywords = @(
        "eval(", "exec(", "Runtime.", "Reflection.", "WebClient", "DownloadString",
        "Invoke-Expression", "IEX", "FromBase64String", "ShellExecute"
    )
    
    foreach ($pattern in $suspiciousPatterns) {
        $files = Get-ChildItem -Path $Path -Recurse -Filter $pattern -ErrorAction SilentlyContinue
        foreach ($file in $files) {
            Write-Report "Arquivo binário/suspeito encontrado: $($file.FullName)" "WARNING"
        }
    }
    
    # Verifica arquivos de código por padrões suspeitos
    $codeFiles = Get-ChildItem -Path $Path -Recurse -Include "*.cs", "*.cshtml", "*.config" -ErrorAction SilentlyContinue
    
    foreach ($file in $codeFiles) {
        try {
            $content = Get-Content $file.FullName -Raw -ErrorAction Stop
            foreach ($keyword in $suspiciousKeywords) {
                if ($content -match $keyword) {
                    Write-Report "Padrão suspeito encontrado em $($file.Name): $keyword" "WARNING"
                }
            }
        }
        catch {
            # Ignora arquivos que não podem ser lidos
        }
    }
}

function Check-BuildFiles {
    param([string]$Path)
    
    Write-Report "Verificando arquivos de build..." "INFO"
    
    $buildFiles = Get-ChildItem -Path $Path -Recurse -Include "*.props", "*.targets" -ErrorAction SilentlyContinue
    
    foreach ($file in $buildFiles) {
        Write-Report "Arquivo de build encontrado: $($file.FullName)" "INFO"
        
        try {
            $content = Get-Content $file.FullName -Raw
            # Verifica por comandos suspeitos em arquivos de build
            $suspiciousBuildPatterns = @(
                "Exec", "DownloadFile", "Invoke", "Script", "PowerShell"
            )
            
            foreach ($pattern in $suspiciousBuildPatterns) {
                if ($content -match $pattern) {
                    Write-Report "Comando suspeito em arquivo de build $($file.Name): $pattern" "WARNING"
                }
            }
        }
        catch {
            Write-Report "Não foi possível ler o arquivo: $($file.Name)" "WARNING"
        }
    }
}

function Analyze-NuGetConfig {
    param([string]$Path)
    
    Write-Report "Analisando configurações do NuGet..." "INFO"
    
    $nugetConfigs = Get-ChildItem -Path $Path -Recurse -Filter "nuget.config" -ErrorAction SilentlyContinue
    
    foreach ($config in $nugetConfigs) {
        Write-Report "Arquivo NuGet.config encontrado: $($config.FullName)" "INFO"
        
        try {
            $content = Get-Content $config.FullName -Raw
            
            # Verifica por sources suspeitas
            if ($content -match "http://" -and $content -notmatch "https://nuget.org" -and $content -notmatch "https://api.nuget.org") {
                Write-Report "Fonte HTTP não segura encontrada em NuGet.config" "WARNING"
            }
            
            # Verifica por sources personalizadas suspeitas
            if ($content -match "packages.local" -or $content -match "localhost") {
                Write-Report "Fonte local/personalizada encontrada em NuGet.config" "WARNING"
            }
        }
        catch {
            Write-Report "Erro ao analisar NuGet.config: $($_.Exception.Message)" "WARNING"
        }
    }
}

function Generate-SecurityReport {
    param([string]$Path)
    
    Write-Report "Gerando relatório de segurança completo..." "INFO"
    Write-Report "==========================================" "INFO"
    
    # 1. Verifica instalação do .NET
    if (-not (Test-DotNetInstallation)) {
        return
    }
    
    # 2. Encontra arquivos do projeto
    $projectFiles = Get-ProjectFiles -Path $Path
    
    Write-Report "Soluções encontradas: $($projectFiles.SolutionFiles.Count)" "INFO"
    Write-Report "Projetos encontrados: $($projectFiles.CsProjFiles.Count)" "INFO"
    
    # 3. Analisa cada projeto
    foreach ($project in $projectFiles.CsProjFiles) {
        Write-Report "=== ANALISANDO PROJETO: $($project.Name) ===" "INFO"
        
        if ($CheckDependencies) {
            Analyze-Dependencies -ProjectFile $project
        }
    }
    
    # 4. Verifica arquivos suspeitos
    Check-SuspiciousFiles -Path $Path
    
    # 5. Verifica arquivos de build
    Check-BuildFiles -Path $Path
    
    # 6. Analisa configurações do NuGet
    Analyze-NuGetConfig -Path $Path
    
    # 7. Scan profundo (opcional)
    if ($DeepScan) {
        Write-Report "Executando varredura profunda..." "INFO"
        # Aqui você pode adicionar verificações adicionais
        # - Análise de hashes de arquivos
        # - Verificação de certificados
        # - Scan com ferramentas externas
    }
    
    Write-Report "Varredura concluída! Relatório salvo em: $OutputFile" "SUCCESS"
    Write-Report "==========================================" "INFO"
}

# Executa a varredura
try {
    # Cria arquivo de relatório
    "=== RELATÓRIO DE SEGURANÇA .NET CORE ===" | Out-File -FilePath $OutputFile
    "Data: $(Get-Date)" | Add-Content -Path $OutputFile
    "Diretório: $ProjectPath" | Add-Content -Path $OutputFile
    "" | Add-Content -Path $OutputFile
    
    Generate-SecurityReport -Path $ProjectPath
    
    # Mostra resumo final
    $reportContent = Get-Content $OutputFile
    $criticalCount = ($reportContent | Where-Object { $_ -match "CRITICAL" }).Count
    $warningCount = ($reportContent | Where-Object { $_ -match "WARNING" }).Count
    
    Write-Host "`n=== RESUMO DA VARREdura ===" -ForegroundColor Cyan
    Write-Host "Críticos: $criticalCount" -ForegroundColor $(if ($criticalCount -gt 0) { "Red" } else { "Green" })
    Write-Host "Avisos: $warningCount" -ForegroundColor $(if ($warningCount -gt 0) { "Yellow" } else { "Green" })
    Write-Host "Relatório completo: $OutputFile" -ForegroundColor Cyan
}
catch {
    Write-Host "Erro durante a varredura: $($_.Exception.Message)" -ForegroundColor Red
}
