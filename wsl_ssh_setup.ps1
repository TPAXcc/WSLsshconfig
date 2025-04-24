#Requires -RunAsAdministrator

<#
.SYNOPSIS
�Զ�����WSL SSH���ӻ�����֧��ѡ��WSL���а棩
.DESCRIPTION
������ǿ��
1. ��ǿ�͹���ԱȨ����֤
2. ����WSL���а���
3. ˫��IP��ȡ���ƣ�IPv4/IPv6��
4. ����ʽ����ǽ�������
5. ��Կ��ȫ��ǿ��ʩ
#>

#region ��ʼ������
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

# ǿ��Ȩ�޼�飨˫����֤��
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "���󣺱���ʹ�ù���ԱȨ�����У�" -ForegroundColor Red
    exit 1
}

# ��ǿ��־ϵͳ
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
        Write-Host "���ö�ջ��`n$stackTrace" -ForegroundColor DarkGray
    }
}
#endregion

#region WSLʵ�����
function Get-ValidWslDistros {
    try {
        Write-EnhancedLog "���ڼ��WSL����..." -Level Debug
        
        # ��ȡԭʼ���а��б�ʹ��--quietȷ���ɾ������
        $distros = wsl.exe --list --all --quiet 2>&1 | 
            Where-Object { 
                $_ -notmatch '^$|docker-desktop|^(\s*\*?\s*)?Name$' -and
                $_ -match '\S' 
            }

        if (-not $distros) {
            throw "δ�ҵ���ЧWSL���а�"
        }
        
        return @($distros)
    }
    catch {
        Write-EnhancedLog "WSL���ʧ�ܣ�$_" -Level Error -IncludeStackTrace
        exit 1
    }
}

$validDistros = Get-ValidWslDistros

# ����ʽѡ���߼�
if ($validDistros.Count -eq 1) {
    $selectedDistro = $validDistros[0]
    Write-EnhancedLog "�Զ�ѡ��Ψһ���а棺$selectedDistro" -Level Info
}
else {
    Write-Host "`n��⵽���WSL���а棺"
    $validDistros | ForEach-Object { "[$($validDistros.IndexOf($_)+1)] $_" }
    
    do {
        $selection = Read-Host "`n������ѡ���� (1-$($validDistros.Count))"
        $index = [int]$selection - 1
    } while ($index -lt 0 -or $index -ge $validDistros.Count)
    
    $selectedDistro = $validDistros[$index]
    Write-EnhancedLog "��ѡ���а棺$selectedDistro" -Level Info
}
#endregion

#region ��������
function Get-WslNetworkInfo {
    param(
        [Parameter(Mandatory=$true)]
        [string]$selectedDistro
    )
    
    try {
        echo "try1"
        $selectedDistro = "$selectedDistro"
        $selectedDistro = $selectedDistro.Trim()
         # ����״̬���
        Write-EnhancedLog "���WSL��������״̬..." -Level Debug
        $runningDistros = wsl.exe --list --running --quiet 2>&1
        
        if (-not ($runningDistros -match "$selectedDistro")) {
            throw "WSL���� $selectedDistro δ���У����������÷��а�"
            exit 1
        }
        

        Write-EnhancedLog "���ڻ�ȡ��������..." -Level Debug

        # ��⾵��ģʽ�������¾����ø�ʽ��
        $wslConfigPath = "$env:USERPROFILE\.wslconfig"
        $mirrorMode = $false
        if (Test-Path $wslConfigPath) {
            $content = Get-Content $wslConfigPath | Where-Object { 
                $_ -match '^\s*networkingMode\s*=\s*mirrored\s*$' 
            }
            $mirrorMode = [bool]$content
        }

        if ($mirrorMode) {
            Write-EnhancedLog "��⵽��������ģʽ" -Level Warning
            return @{ IP = '127.0.0.1'; IsMirrored = $true }
        }

        # ʹ��΢��ٷ��Ƽ���wsl hostname�����ȡIP
        try {
            echo "ִ�� try2"
            # ��ȡԭʼIP�������IPv4��IPv6��
            $rawOutput = (wsl.exe hostname -I 2>&1) 
            Write-Host "rawOutput: $rawOutput"

            # ����IPv4��IPv6��ַ
            $ipAddresses = $rawOutput -split '\s+' | Where-Object { $_ -match '[^\s]' }
            Write-Host "ipAddresses: $ipAddresses"

            # ʹ��������ʽ��ȷƥ��
            $ipv4 = $ipAddresses | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' } | Select-Object -First 1
            $ipv6 = $ipAddresses | Where-Object { $_ -match '^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$' } | Select-Object -First 1
            Write-Host "ipv4: $ipv4"
            Write-Host "ipv6: $ipv6"

            # ��Ч����֤
            if (-not $ipv4 -or $ipv4 -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
                throw "�޷�ͨ��wsl hostname��ȡ��ЧIPv4��ַ"
            }
        } catch {
            Write-Host "����: $_"
        }

        return [hashtable]@{ 
            IP = $ipv4
            IPv6 = $ipv6
            IsMirrored = $false 
        }
    } 
    catch {
        Write-EnhancedLog "�������ô���$_" -Level Error -IncludeStackTrace
        exit 1
    }
}

$networkInfo = Get-WslNetworkInfo -selectedDistro $selectedDistro
$wslIp = $networkInfo.IP

# �˿�ת�����ã�����IPv6֧�֣�
function Update-PortForwarding {
    param(
        [string]$selectedDistro,
        [int]$Port,
        [string]$AccessScope,
        [hashtable]$NetworkInfo
    )
    
    try {
        Write-EnhancedLog "���ö˿�ת��..." -Level Info
        
        # ɾ���ɹ�������IPv6����
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
            # IPv4����
            netsh interface portproxy delete v4tov4 `
                listenaddress=$address `
                listenport=$Port *>$null
            
            # IPv6����
            netsh interface portproxy delete v6tov4 `
                listenaddress=$address `
                listenport=$Port *>$null
        }
        
        # ����¹��򣨾���ģʽ���⴦��
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
        
        # �־û����ã�����WSL2�����ԣ�
        $persistScript = @'
#!/bin/bash
# ���systemd֧��
if [ -d /run/systemd/system ]; then
    sudo mkdir -p /etc/systemd/system/rc-local.service.d
    echo -e '[Install]\nWantedBy=multi-user.target' | sudo tee /etc/systemd/system/rc-local.service.d/enable.conf
    echo '#!/bin/bash' | sudo tee /etc/rc.local
    sudo chmod +x /etc/rc.local
fi

# ���¶˿�ת��
sudo sed -i '/portproxy/d' /etc/rc.local 2>/dev/null
echo "netsh interface portproxy add v4tov4 listenport=$Port connectport=22 connectaddress=$connectProtocol" | 
sudo tee -a /etc/rc.local >/dev/null
sudo chmod +x /etc/rc.local
'@
        
        $tempScript = New-TemporaryFile
        $persistScript | Out-File $tempScript.FullName -Encoding ASCII
        wsl.exe -- bash -c 'sudo bash `"$(wslpath $tempScript.FullName)`" '
        Remove-Item $tempScript.FullName -Force
        
        Write-EnhancedLog "�˿�ת���������" -Level Info
    }
    catch {
        Write-EnhancedLog "�˿�ת��ʧ�ܣ�$_" -Level Error -IncludeStackTrace
        exit 1
    }
}

Update-PortForwarding -DistroName $selectedDistro -Port $SSH_PORT `
    -AccessScope $AccessScope -NetworkInfo $networkInfo

# ����ǽ�����������Э��������֤��
function Update-FirewallRules {
    param(
        [int]$Port,
        [string]$AccessScope
    )
    
    try {
        Write-EnhancedLog "���÷���ǽ����..." -Level Info
        
        $ruleName = "WSL_SSH_${Port}_$([guid]::NewGuid().ToString('N'))"
        
        # ɾ���ɹ��򣨾�ȷƥ�䣩
        Get-NetFirewallRule -DisplayName "WSL SSH Port $Port" -ErrorAction SilentlyContinue | 
        ForEach-Object {
            Write-EnhancedLog "ɾ���ɹ���$($_.Name)" -Level Debug
            $_ | Remove-NetFirewallRule -Confirm:$false
        }
        
        # �����¹�������Э����֤��
        $profileMap = @{
            "LocalOnly" = @('Domain', 'Private')
            "LAN"       = @('Public')
            "Both"      = @('Domain', 'Private', 'Public')
        }[$AccessScope]
        
        $params = @{
            Name           = $ruleName
            DisplayName    = "WSL SSH Port $Port"
            Description    = "�Զ����ɵ�WSL SSH���ʹ���"
            Direction      = "Inbound"
            Protocol       = "TCP"  # ������TCPЭ��
            LocalPort      = $Port
            Action         = "Allow"
            Enabled        = "True"
            Profile        = $profileMap
            ErrorAction    = "Stop"
        }
        
        New-NetFirewallRule @params | Out-Null
        
        Write-EnhancedLog "����ǽ�����������" -Level Info
    }
    catch {
        Write-EnhancedLog "����ǽ����ʧ�ܣ�$_" -Level Error -IncludeStackTrace
        exit 1
    }
}

Update-FirewallRules -Port $SSH_PORT -AccessScope $AccessScope
#endregion

#region ��ȫ���ã���ǿ��ԿȨ�ޣ�
function Initialize-SshEnvironment {
    param(
        [string]$selectedDistro,
        [string]$UserName
    )
    
    try {
        Write-EnhancedLog "��ʼ��SSH����..." -Level Info
        
        # ��Կ���ɣ���ǿ��Կ���ͼ�⣩
        $keyPath = "$env:USERPROFILE\.ssh\wsl_${DistroName}_ed25519"
        $keyPath = $keyPath.Trim()
        Write-Host "��ǰ·����'$keyPath'"
        if (-not (Test-Path  $keyPath)) {
            ssh-keygen -t ed25519 -f $keyPath -N '""' -C "wsl-ssh-$selectedDistro" -q *>$null
            Write-EnhancedLog "������ED25519��Կ�ԣ�$keyPath" -Level Info
        }
        
        # Windows��Ȩ�����ã���ǿȨ�޿��ƣ�
        $acl = Get-Acl $keyPath
        $acl.SetAccessRuleProtection($true, $false) # ���ü̳�
        $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
        $acl.AddAccessRule(
            [System.Security.AccessControl.FileSystemAccessRule]::new(
                $env:USERNAME, 
                [System.Security.AccessControl.FileSystemRights]::Read,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
        )
        Set-Acl -Path $keyPath -AclObject $acl
        
        # WSL�����ã�����ʽ���ã�
        $setupScript = @'
#!/bin/bash
# �û���������ʽ������
if ! id -u ${UserName} >/dev/null 2>&1; then
    sudo useradd -m -s /bin/bash -G sudo ${UserName}
    echo '${UserName}:$(openssl rand -base64 32)' | sudo chpasswd
    sudo passwd -d ${UserName}
fi

# ��ȫĿ¼����
sudo mkdir -p /home/${UserName}/.ssh
echo '$(Get-Content "${keyPath}.pub")' | sudo tee /home/${UserName}/.ssh/authorized_keys >/dev/null
sudo chmod 700 /home/${UserName}/.ssh
sudo chmod 600 /home/${UserName}/.ssh/authorized_keys
sudo chown -R ${UserName}:${UserName} /home/${UserName}/.ssh

# ��Ȩ������СȨ��ԭ��
sudo rm -f /etc/sudoers.d/90-wsl-ssh-${UserName}
echo '${UserName} ALL=(ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers.d/90-wsl-ssh-${UserName} >/dev/null
sudo chmod 440 /etc/sudoers.d/90-wsl-ssh-${UserName}

# SSH�ӹ����ã����ݲ�ͬ���а棩
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

# �����������systemd�ͷ�systemd��
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
        
        Write-EnhancedLog "SSH������ʼ�����" -Level Info
    }
    catch {
        Write-EnhancedLog "SSH����ʧ�ܣ�$_" -Level Error -IncludeStackTrace
        exit 1
    }
}

Initialize-SshEnvironment -DistroName $selectedDistro -UserName $WSL_USER
#endregion

#region �ͻ������ã�����ʽ���ã�
function Update-SshClientConfig {
    param(
        [string]$selectedDistro,
        [int]$Port,
        [string]$KeyPath,
        [string]$AccessScope,
        [hashtable]$NetworkInfo
    )
    
    try {
        Write-EnhancedLog "����SSH�ͻ�������..." -Level Info
        
        $externalIp = if ($AccessScope -ne "LocalOnly") {
            (Get-NetIPAddress | 
             Where-Object { 
                 $_.AddressFamily -eq 'IPv4' -and 
                 $_.InterfaceAlias -notmatch 'Loopback|Virtual' -and
                 $_.IPAddress -notmatch '^(169\.254|127\.)' 
             } | Select-Object -First 1).IPAddress
        }
        
        $configContent = @"
# WSL�Զ����� - $selectedDistro
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
        
        # ��ȫ���ݣ�����7�죩
        $configPath = "$sshDir\config"
        if (Test-Path $configPath) {
            $backupDir = "$sshDir\backup"
            New-Item -Path $backupDir -ItemType Directory -Force | Out-Null
            $backupPath = "$backupDir\config_$(Get-Date -Format 'yyyyMMdd').bak"
            Copy-Item $configPath $backupPath -Force
            Get-ChildItem $backupDir\*.bak | Sort-Object -Property CreationTime -Desc | Select-Object -Skip 7 | Remove-Item -Force
        }
        
        # ���ܺϲ����ã�����ʽ�滻��
        $existingContent = if (Test-Path $configPath) {
            [System.Collections.ArrayList](Get-Content $configPath)
        } else {
            New-Object System.Collections.ArrayList
        }

        # ɾ�������ÿ�
        $startIndex = $existingContent.IndexOf("# WSL�Զ����� - $selectedDistro")
        if ($startIndex -ge 0) {
            $endIndex = $startIndex
            while ($endIndex -lt $existingContent.Count -and 
                  -not $existingContent[$endIndex].StartsWith("# WSL�Զ����� -")) {
                $endIndex++
            }
            $existingContent.RemoveRange($startIndex, $endIndex - $startIndex + 1)
        }

        # ����������
        $newLines = $configContent -split "`n"
        $existingContent.InsertRange(0, $newLines)
        
        # ��������
        $existingContent | Out-File $configPath -Encoding UTF8 -Force
        
        Write-EnhancedLog "�ͻ������ø������" -Level Info
    }
    catch {
        Write-EnhancedLog "�ͻ�������ʧ�ܣ�$_" -Level Error -IncludeStackTrace
    }
}

$keyPath = "$env:USERPROFILE\.ssh\wsl_${selectedDistro}_ed25519"
Update-SshClientConfig -DistroName $selectedDistro -Port $SSH_PORT `
    -KeyPath $keyPath -AccessScope $AccessScope -NetworkInfo $networkInfo
#endregion

# ��ɱ���
Write-Host @"
�X�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�[
�U                 ���óɹ�!                   �U
�d�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�g
�U ��ѡ���а棺$($selectedDistro.PadRight(33)) �U
�U �����˿ڣ�$($SSH_PORT.ToString().PadRight(34)) �U
�U ���ʷ�Χ��$($AccessScope.PadRight(33)) �U
�U �û����ƣ�$($WSL_USER.PadRight(33)) �U
�U ��Կ·����$($keyPath.PadRight(33)) �U
�^�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�a
"@ -ForegroundColor Cyan

Read-Host "`n�� Enter �˳�..."