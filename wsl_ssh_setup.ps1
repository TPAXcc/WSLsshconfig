#Requires -RunAsAdministrator

<#
.SYNOPSIS
自动配置WSL SSH连接环境（支持选择WSL发行版）
.DESCRIPTION
功能增强：
1. 增强型管理员权限验证
2. 智能WSL发行版检测
3. 双重IP获取机制（IPv4/IPv6）
4. 防御式防火墙规则管理
5. 密钥安全增强措施
#>

#region 初始化配置
param(
    [Parameter(Mandatory=$false)]
    [ValidateRange(1,65535)]
    [int]$SSH_PORT = "2222",
    
    [Parameter(Mandatory=$false)]
    [ValidatePattern('^[a-z_][a-z0-9_-]{1,31}$')]
    [string]$WSL_USER = "wsl_ssh_user",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("LocalOnly","LAN","Both")]
    [string]$AccessScope = "LocalOnly"
)

# 强化权限检查（双重验证）
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "错误：必须使用管理员权限运行！" -ForegroundColor Red
    exit 1
}

# 增强日志系统
enum LogLevel {
    Info
    Warning
    Error
    Debug
}

function Write-EnhancedLog {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [LogLevel]$Level = [LogLevel]::Info,
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeStackTrace
    )
    
    $logEntry = @{
        Time    = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
        Level   = $Level.ToString().PadRight(7)
        Message = $Message
    }
    
    $colorSwitch = @{
        [LogLevel]::Info    = 'Cyan'
        [LogLevel]::Warning = 'Yellow'
        [LogLevel]::Error   = 'Red'
        [LogLevel]::Debug   = 'Gray'
    }[$Level]

    $logLine = "[$($logEntry.Time)] [$($logEntry.Level)] $($logEntry.Message)"
    Write-Host $logLine -ForegroundColor $colorSwitch

    if ($IncludeStackTrace) {
        $stackTrace = (Get-PSCallStack | Select-Object -Skip 1 | Format-Table -AutoSize | Out-String).Trim()
        Write-Host "调用堆栈：`n$stackTrace" -ForegroundColor DarkGray
    }
}
#endregion

#region WSL实例检测
function Get-ValidWslDistros {
    try {
        Write-EnhancedLog "正在检测WSL环境..." -Level Debug
        
        # 获取原始发行版列表（使用--quiet确保干净输出）
        $distros = wsl.exe --list --all --quiet 2>&1 | 
            Where-Object { 
                $_ -notmatch '^$|docker-desktop|^(\s*\*?\s*)?Name$' -and
                $_ -match '\S' 
            }

        if (-not $distros) {
            throw "未找到有效WSL发行版"
        }
        
        return @($distros)
    }
    catch {
        Write-EnhancedLog "WSL检测失败：$_" -Level Error -IncludeStackTrace
        exit 1
    }
}

$validDistros = Get-ValidWslDistros

# 交互式选择逻辑
if ($validDistros.Count -eq 1) {
    $selectedDistro = $validDistros[0]
    Write-EnhancedLog "自动选择唯一发行版：$selectedDistro" -Level Info
}
else {
    Write-Host "`n检测到多个WSL发行版："
    $validDistros | ForEach-Object { "[$($validDistros.IndexOf($_)+1)] $_" }
    
    do {
        $selection = Read-Host "`n请输入选择编号 (1-$($validDistros.Count))"
        $index = [int]$selection - 1
    } while ($index -lt 0 -or $index -ge $validDistros.Count)
    
    $selectedDistro = $validDistros[$index]
    Write-EnhancedLog "已选择发行版：$selectedDistro" -Level Info
}
#endregion

#region 网络配置
function Get-WslNetworkInfo {
    param(
        [Parameter(Mandatory=$true)]
        [string]$selectedDistro
    )
    
    try {
        echo "try1"
        $selectedDistro = "$selectedDistro"
        $selectedDistro = $selectedDistro.Trim()
         # 运行状态检测
        Write-EnhancedLog "检测WSL容器运行状态..." -Level Debug
        $runningDistros = wsl.exe --list --running --quiet 2>&1
        
        if (-not ($runningDistros -match "$selectedDistro")) {
            throw "WSL容器 $selectedDistro 未运行，请先启动该发行版"
            exit 1
        }
        

        Write-EnhancedLog "正在获取网络配置..." -Level Debug

        # 检测镜像模式（兼容新旧配置格式）
        $wslConfigPath = "$env:USERPROFILE\.wslconfig"
        $mirrorMode = $false
        if (Test-Path $wslConfigPath) {
            $content = Get-Content $wslConfigPath | Where-Object { 
                $_ -match '^\s*networkingMode\s*=\s*mirrored\s*$' 
            }
            $mirrorMode = [bool]$content
        }

        if ($mirrorMode) {
            Write-EnhancedLog "检测到镜像网络模式" -Level Warning
            return @{ IP = '127.0.0.1'; IsMirrored = $true }
        }

        # 使用微软官方推荐的wsl hostname命令获取IP
        try {
            echo "执行 try2"
            # 获取原始IP输出（含IPv4和IPv6）
            $rawOutput = (wsl.exe hostname -I 2>&1) 
            Write-Host "rawOutput: $rawOutput"

            # 分离IPv4和IPv6地址
            $ipAddresses = $rawOutput -split '\s+' | Where-Object { $_ -match '[^\s]' }
            Write-Host "ipAddresses: $ipAddresses"

            # 使用正则表达式精确匹配
            $ipv4 = $ipAddresses | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' } | Select-Object -First 1
            $ipv6 = $ipAddresses | Where-Object { $_ -match '^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$' } | Select-Object -First 1
            Write-Host "ipv4: $ipv4"
            Write-Host "ipv6: $ipv6"

            # 有效性验证
            if (-not $ipv4 -or $ipv4 -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
                throw "无法通过wsl hostname获取有效IPv4地址"
            }
        } catch {
            Write-Host "错误: $_"
        }

        return [hashtable]@{ 
            IP = $ipv4
            IPv6 = $ipv6
            IsMirrored = $false 
        }
    } 
    catch {
        Write-EnhancedLog "网络配置错误：$_" -Level Error -IncludeStackTrace
        exit 1
    }
}

$networkInfo = Get-WslNetworkInfo -selectedDistro $selectedDistro
$wslIp = $networkInfo.IP

# 端口转发配置（增加IPv6支持）
function Update-PortForwarding {
    param(
        [string]$selectedDistro,
        [int]$Port,
        [string]$AccessScope,
        [hashtable]$NetworkInfo
    )
    
    try {
        Write-EnhancedLog "配置端口转发..." -Level Info
        
        # 删除旧规则（增加IPv6处理）
        $listenAddresses = switch ($AccessScope) {
            "LocalOnly" { 
                @('127.0.0.1', '::1') 
            }
            "LAN"       { 
                @('0.0.0.0', '::') 
            }
            default     { 
                @('127.0.0.1', '::1', '0.0.0.0', '::') 
            }
        }
        
        foreach ($address in $listenAddresses) {
            # IPv4规则
            netsh interface portproxy delete v4tov4 `
                listenaddress=$address `
                listenport=$Port *>$null
            
            # IPv6规则
            netsh interface portproxy delete v6tov4 `
                listenaddress=$address `
                listenport=$Port *>$null
        }
        
        # 添加新规则（镜像模式特殊处理）
        $connectProtocol = if ($NetworkInfo.IsMirrored) { 
            "localhost" 
        } else { 
            $NetworkInfo.IP 
        }

        $rules = @()
        if ($AccessScope -in "LAN","Both") {
            $rules += @{
                Type    = 'v4tov4'
                Address = '0.0.0.0'
                Port    = $Port
                Connect = $connectProtocol
            }
            $rules += @{
                Type    = 'v6tov4'
                Address = '::'
                Port    = $Port
                Connect = $connectProtocol
            }
        }
        
        if ($AccessScope -in "LocalOnly","Both") {
            $rules += @{
                Type    = 'v4tov4'
                Address = '127.0.0.1'
                Port    = $Port
                Connect = $connectProtocol
            }
            $rules += @{
                Type    = 'v6tov4'
                Address = '::1'
                Port    = $Port
                Connect = $connectProtocol
            }
        }

        foreach ($rule in $rules) {
            netsh interface portproxy add $rule.Type `
                listenaddress=$($rule.Address) `
                listenport=$($rule.Port) `
                connectaddress=$($rule.Connect) `
                connectport=22
        }
        
        # 持久化配置（增加WSL2兼容性）
        $persistScript = @'
#!/bin/bash
# 检测systemd支持
if [ -d /run/systemd/system ]; then
    sudo mkdir -p /etc/systemd/system/rc-local.service.d
    echo -e '[Install]\nWantedBy=multi-user.target' | sudo tee /etc/systemd/system/rc-local.service.d/enable.conf
    echo '#!/bin/bash' | sudo tee /etc/rc.local
    sudo chmod +x /etc/rc.local
fi

# 更新端口转发
sudo sed -i '/portproxy/d' /etc/rc.local 2>/dev/null
echo "netsh interface portproxy add v4tov4 listenport=$Port connectport=22 connectaddress=$connectProtocol" | 
sudo tee -a /etc/rc.local >/dev/null
sudo chmod +x /etc/rc.local
'@
        
        $tempScript = New-TemporaryFile
        $persistScript | Out-File $tempScript.FullName -Encoding ASCII
        wsl.exe -- bash -c 'sudo bash `"$(wslpath $tempScript.FullName)`" '
        Remove-Item $tempScript.FullName -Force
        
        Write-EnhancedLog "端口转发配置完成" -Level Info
    }
    catch {
        Write-EnhancedLog "端口转发失败：$_" -Level Error -IncludeStackTrace
        exit 1
    }
}

Update-PortForwarding -DistroName $selectedDistro -Port $SSH_PORT `
    -AccessScope $AccessScope -NetworkInfo $networkInfo

# 防火墙规则管理（增加协议类型验证）
function Update-FirewallRules {
    param(
        [int]$Port,
        [string]$AccessScope
    )
    
    try {
        Write-EnhancedLog "配置防火墙规则..." -Level Info
        
        $ruleName = "WSL_SSH_${Port}_$([guid]::NewGuid().ToString('N'))"
        
        # 删除旧规则（精确匹配）
        Get-NetFirewallRule -DisplayName "WSL SSH Port $Port" -ErrorAction SilentlyContinue | 
        ForEach-Object {
            Write-EnhancedLog "删除旧规则：$($_.Name)" -Level Debug
            $_ | Remove-NetFirewallRule -Confirm:$false
        }
        
        # 创建新规则（增加协议验证）
        $profileMap = @{
            "LocalOnly" = @('Domain', 'Private')
            "LAN"       = @('Public')
            "Both"      = @('Domain', 'Private', 'Public')
        }[$AccessScope]
        
        $params = @{
            Name           = $ruleName
            DisplayName    = "WSL SSH Port $Port"
            Description    = "自动生成的WSL SSH访问规则"
            Direction      = "Inbound"
            Protocol       = "TCP"  # 仅允许TCP协议
            LocalPort      = $Port
            Action         = "Allow"
            Enabled        = "True"
            Profile        = $profileMap
            ErrorAction    = "Stop"
        }
        
        New-NetFirewallRule @params | Out-Null
        
        Write-EnhancedLog "防火墙规则配置完成" -Level Info
    }
    catch {
        Write-EnhancedLog "防火墙配置失败：$_" -Level Error -IncludeStackTrace
        exit 1
    }
}

Update-FirewallRules -Port $SSH_PORT -AccessScope $AccessScope
#endregion

#region 安全配置（增强密钥权限）
function Initialize-SshEnvironment {
    param(
        [string]$selectedDistro,
        [string]$UserName
    )
    
    try {
        Write-EnhancedLog "初始化SSH环境..." -Level Info
        
        # 密钥生成（增强密钥类型检测）
        $keyPath = "$env:USERPROFILE\.ssh\wsl_${DistroName}_ed25519"
        $keyPath = $keyPath.Trim()
        Write-Host "当前路径：'$keyPath'"
        if (-not (Test-Path  $keyPath)) {
            ssh-keygen -t ed25519 -f $keyPath -N '""' -C "wsl-ssh-$selectedDistro" -q *>$null
            Write-EnhancedLog "已生成ED25519密钥对：$keyPath" -Level Info
        }
        
        # Windows端权限设置（加强权限控制）
        $acl = Get-Acl $keyPath
        $acl.SetAccessRuleProtection($true, $false) # 禁用继承
        $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
        $acl.AddAccessRule(
            [System.Security.AccessControl.FileSystemAccessRule]::new(
                $env:USERNAME, 
                [System.Security.AccessControl.FileSystemRights]::Read,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
        )
        Set-Acl -Path $keyPath -AclObject $acl
        
        # WSL端配置（防御式配置）
        $setupScript = @'
#!/bin/bash
# 用户管理（防御式创建）
if ! id -u ${UserName} >/dev/null 2>&1; then
    sudo useradd -m -s /bin/bash -G sudo ${UserName}
    echo '${UserName}:$(openssl rand -base64 32)' | sudo chpasswd
    sudo passwd -d ${UserName}
fi

# 安全目录配置
sudo mkdir -p /home/${UserName}/.ssh
echo '$(Get-Content "${keyPath}.pub")' | sudo tee /home/${UserName}/.ssh/authorized_keys >/dev/null
sudo chmod 700 /home/${UserName}/.ssh
sudo chmod 600 /home/${UserName}/.ssh/authorized_keys
sudo chown -R ${UserName}:${UserName} /home/${UserName}/.ssh

# 特权管理（最小权限原则）
sudo rm -f /etc/sudoers.d/90-wsl-ssh-${UserName}
echo '${UserName} ALL=(ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers.d/90-wsl-ssh-${UserName} >/dev/null
sudo chmod 440 /etc/sudoers.d/90-wsl-ssh-${UserName}

# SSH加固配置（兼容不同发行版）
sudo sed -i '/^#\?Port /d; /^#\?PasswordAuthentication /d; /^#\?PermitRootLogin /d' /etc/ssh/sshd_config
sudo tee -a /etc/ssh/sshd_config >/dev/null <<EOL
Port 22
PasswordAuthentication no
ChallengeResponseAuthentication no
PermitRootLogin prohibit-password
X11Forwarding no
AllowTcpForwarding yes
ClientAliveInterval 300
ClientAliveCountMax 2
LogLevel VERBOSE
EOL

# 服务管理（兼容systemd和非systemd）
if command -v systemctl >/dev/null; then
    sudo systemctl restart ssh
else
    sudo service ssh restart
fi
'@
        
        $tempScript = New-TemporaryFile
        $setupScript | Out-File $tempScript.FullName -Encoding ASCII
        wsl.exe -- bash -c 'sudo bash `"$(wslpath $tempScript.FullName)`" '
        Remove-Item $tempScript.FullName -Force
        
        Write-EnhancedLog "SSH环境初始化完成" -Level Info
    }
    catch {
        Write-EnhancedLog "SSH配置失败：$_" -Level Error -IncludeStackTrace
        exit 1
    }
}

Initialize-SshEnvironment -DistroName $selectedDistro -UserName $WSL_USER
#endregion

#region 客户端配置（防御式配置）
function Update-SshClientConfig {
    param(
        [string]$selectedDistro,
        [int]$Port,
        [string]$KeyPath,
        [string]$AccessScope,
        [hashtable]$NetworkInfo
    )
    
    try {
        Write-EnhancedLog "更新SSH客户端配置..." -Level Info
        
        $externalIp = if ($AccessScope -ne "LocalOnly") {
            (Get-NetIPAddress | 
             Where-Object { 
                 $_.AddressFamily -eq 'IPv4' -and 
                 $_.InterfaceAlias -notmatch 'Loopback|Virtual' -and
                 $_.IPAddress -notmatch '^(169\.254|127\.)' 
             } | Select-Object -First 1).IPAddress
        }
        
        $configContent = @"
# WSL自动配置 - $selectedDistro
Host $selectedDistro
    HostName localhost
    Port $Port
    User $WSL_USER
    IdentityFile "$KeyPath"
    StrictHostKeyChecking accept-new
    UserKnownHostsFile ~/.ssh/known_hosts.wsl
    ServerAliveInterval 60

"@
        
        if ($externalIp) {
            $configContent += @"
Host ${DistroName}-external
    HostName $externalIp
    Port $Port
    User $WSL_USER
    IdentityFile "$KeyPath"
    StrictHostKeyChecking accept-new
    UserKnownHostsFile ~/.ssh/known_hosts.wsl
    ServerAliveInterval 60

"@
        }
        
        $sshDir = "$env:USERPROFILE\.ssh"
        if (-not (Test-Path $sshDir)) {
            New-Item -Path $sshDir -ItemType Directory -Force | Out-Null
            icacls $sshDir /inheritance:r /grant:r "$env:USERNAME:(OI)(CI)F"
        }
        
        # 安全备份（保留7天）
        $configPath = "$sshDir\config"
        if (Test-Path $configPath) {
            $backupDir = "$sshDir\backup"
            New-Item -Path $backupDir -ItemType Directory -Force | Out-Null
            $backupPath = "$backupDir\config_$(Get-Date -Format 'yyyyMMdd').bak"
            Copy-Item $configPath $backupPath -Force
            Get-ChildItem $backupDir\*.bak | Sort-Object -Property CreationTime -Desc | Select-Object -Skip 7 | Remove-Item -Force
        }
        
        # 智能合并配置（防御式替换）
        $existingContent = if (Test-Path $configPath) {
            [System.Collections.ArrayList](Get-Content $configPath)
        } else {
            New-Object System.Collections.ArrayList
        }

        # 删除旧配置块
        $startIndex = $existingContent.IndexOf("# WSL自动配置 - $selectedDistro")
        if ($startIndex -ge 0) {
            $endIndex = $startIndex
            while ($endIndex -lt $existingContent.Count -and 
                  -not $existingContent[$endIndex].StartsWith("# WSL自动配置 -")) {
                $endIndex++
            }
            $existingContent.RemoveRange($startIndex, $endIndex - $startIndex + 1)
        }

        # 插入新配置
        $newLines = $configContent -split "`n"
        $existingContent.InsertRange(0, $newLines)
        
        # 保存配置
        $existingContent | Out-File $configPath -Encoding UTF8 -Force
        
        Write-EnhancedLog "客户端配置更新完成" -Level Info
    }
    catch {
        Write-EnhancedLog "客户端配置失败：$_" -Level Error -IncludeStackTrace
    }
}

$keyPath = "$env:USERPROFILE\.ssh\wsl_${selectedDistro}_ed25519"
Update-SshClientConfig -DistroName $selectedDistro -Port $SSH_PORT `
    -KeyPath $keyPath -AccessScope $AccessScope -NetworkInfo $networkInfo
#endregion

# 完成报告
Write-Host @"
╔══════════════════════════════════════════════╗
║                 配置成功!                   ║
╠══════════════════════════════════════════════╣
║ 已选发行版：$($selectedDistro.PadRight(33)) ║
║ 监听端口：$($SSH_PORT.ToString().PadRight(34)) ║
║ 访问范围：$($AccessScope.PadRight(33)) ║
║ 用户名称：$($WSL_USER.PadRight(33)) ║
║ 密钥路径：$($keyPath.PadRight(33)) ║
╚══════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Read-Host "`n按 Enter 退出..."