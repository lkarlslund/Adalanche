$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
function Capture($Name, [scriptblock]$Body) {
    $rows = [System.Collections.Generic.List[object]]::new()
    $status = 'collected'
    try {
        & $Body | ForEach-Object {
            if ($rows.Count -ge 10000) { throw 'record-limit' }
            $rows.Add($_)
        }
    } catch {
        $status = 'failed'
        if ($_.Exception -is [UnauthorizedAccessException] -or $_.CategoryInfo.Category -eq 'PermissionDenied') { $status = 'access_denied' }
        if ($_.Exception -is [System.Management.Automation.CommandNotFoundException]) { $status = 'unsupported' }
    }
    @{name=$Name; capture=@{result=@{status=$status}; records=@($rows.ToArray())}} | ConvertTo-Json -Depth 12 -Compress
}
Capture 'smb-client' {
    Get-SmbClientConfiguration | Select-Object RequireSecuritySignature,EnableInsecureGuestLogons,EnableSecuritySignature
}
Capture 'smb-server' {
    Get-SmbServerConfiguration | Select-Object RequireSecuritySignature,EnableSMB1Protocol,EnableSMB2Protocol,EncryptData,RejectUnencryptedAccess
}
Capture 'credential-protection' {
    Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard |
        Select-Object VirtualizationBasedSecurityStatus,SecurityServicesConfigured,SecurityServicesRunning,AvailableSecurityProperties,RequiredSecurityProperties
}
Capture 'lsa-protection-runtime' {
    $boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Wininit'; Id=12; StartTime=$boot} -MaxEvents 1 |
        Select-Object Id,TimeCreated
}
Capture 'service-runtime' {
    Get-CimInstance Win32_Service | Select-Object Name,State,StartMode,StartName,ProcessId
}
Capture 'task-security' {
    $scheduler=New-Object -ComObject Schedule.Service
    $scheduler.Connect()
    $folders=[System.Collections.Generic.Stack[object]]::new()
    $folders.Push($scheduler.GetFolder('\'))
    $visited=0
    while ($folders.Count -gt 0) {
        if (++$visited -gt 10000) { throw 'folder-limit' }
        $folder=$folders.Pop()
        foreach ($task in $folder.GetTasks(1)) {
            $sddl=$null; $status='collected'
            try { $sddl=$task.GetSecurityDescriptor(4) }
            catch {
                $status='failed'
                if (($_.Exception.HResult -band 0xffff) -eq 5) { $status='access_denied' }
            }
            [pscustomobject]@{Path=$task.Path; SDDL=$sddl; Result=@{Status=$status}}
        }
        foreach ($child in $folder.GetFolders(0)) { $folders.Push($child) }
    }
}
Capture 'listeners' {
    Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess
}
Capture 'firewall-profiles' {
    Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {
        [pscustomobject]@{Name=$_.Name; Enabled=[int]$_.Enabled; DefaultInboundAction=[string]$_.DefaultInboundAction; DefaultOutboundAction=[string]$_.DefaultOutboundAction}
    }
}
Capture 'network-profiles' {
    Get-NetConnectionProfile | Select-Object InterfaceIndex,NetworkCategory,IPv4Connectivity,IPv6Connectivity
}
Capture 'firewall-rules' {
    Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True | ForEach-Object {
        $rule=$_
        $ports=@($rule | Get-NetFirewallPortFilter | Select-Object Protocol,LocalPort,RemotePort)
        $addresses=@($rule | Get-NetFirewallAddressFilter | Select-Object LocalAddress,RemoteAddress)
        [pscustomobject]@{Name=$rule.Name; Direction=[string]$rule.Direction; Action=[string]$rule.Action; Profile=[string]$rule.Profile; Ports=$ports; Addresses=$addresses}
    }
}
Capture 'remote-endpoints' {
    Get-PSSessionConfiguration | Select-Object Name,Permission,SecurityDescriptorSddl,RunAsUser
}
Capture 'remote-listeners' {
    Get-ChildItem WSMan:\localhost\Listener | ForEach-Object {
        $values=@{}
        Get-ChildItem $_.PSPath | Where-Object Name -in @('Address','Transport','Port','Enabled','URLPrefix','CertificateThumbprint') | ForEach-Object { $values[$_.Name]=$_.Value }
        [pscustomobject]$values
    }
}
Capture 'startup' {
    Get-CimInstance Win32_StartupCommand | ForEach-Object {
        $command=[string]$_.Command
        $path=$null
        if ($command -match '^\s*"([^"]+)"') { $path=$matches[1] }
        elseif ($command -match '^\s*(\S+\.exe)(?:\s|$)') { $path=$matches[1] }
        [pscustomobject]@{Name=$_.Name; Location=$_.Location; User=$_.User; UserSID=$_.UserSID; Executable=$path; PathResolved=($null -ne $path)}
    }
}
Capture 'event-subscriptions' {
    Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding | ForEach-Object {
        # Project reference keys explicitly; never serialize a consumer instance.
        [pscustomobject]@{FilterName=$_.Filter.Name; FilterClass=$_.Filter.CimClass.CimClassName; ConsumerName=$_.Consumer.Name; ConsumerClass=$_.Consumer.CimClass.CimClassName; CreatorSID=$_.CreatorSID}
    }
}
Capture 'event-consumers' {
    Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer | ForEach-Object {
        [pscustomobject]@{Class=$_.CimClass.CimClassName; Name=$_.Name; Executable=$_.ExecutablePath; ScriptFile=$_.ScriptFileName; CreatorSID=$_.CreatorSID; HasEmbeddedScript=($null -ne $_.ScriptText)}
    }
}
Capture 'machine-certificates' {
    Get-ChildItem Cert:\LocalMachine\My | ForEach-Object {
        $cert=$_; $keyPath=$null; $keyStatus='not_requested'; $key=$null
        if ($cert.HasPrivateKey) {
            try {
                $key=[System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
                if ($key -is [System.Security.Cryptography.RSACng] -and $key.Key.IsMachineKey) { $keyPath=Join-Path $env:ProgramData ('Microsoft\Crypto\Keys\'+$key.Key.UniqueName); $keyStatus='collected' }
                elseif ($key -is [System.Security.Cryptography.RSACryptoServiceProvider] -and $key.CspKeyContainerInfo.MachineKeyStore) { $keyPath=Join-Path $env:ProgramData ('Microsoft\Crypto\RSA\MachineKeys\'+$key.CspKeyContainerInfo.UniqueKeyContainerName); $keyStatus='collected' }
                else { $keyStatus='unsupported' }
            } catch { $keyStatus='failed' }
            finally { if ($null -ne $key) { $key.Dispose() } }
        }
        [pscustomobject]@{Thumbprint=$cert.Thumbprint; NotBefore=$cert.NotBefore; NotAfter=$cert.NotAfter; HasPrivateKey=$cert.HasPrivateKey; EnhancedKeyUsage=@($cert.EnhancedKeyUsageList | ForEach-Object {$_.ObjectId.Value}); KeyPath=$keyPath; KeyMetadataStatus=$keyStatus}
    }
}
Capture 'credential-locations' {
    Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' | ForEach-Object {
        $sid=$_.PSChildName; $profile=(Get-ItemProperty $_.PSPath -Name ProfileImagePath).ProfileImagePath
        foreach ($relative in @('AppData\Local\Microsoft\Credentials','AppData\Roaming\Microsoft\Credentials','AppData\Local\Microsoft\Vault','AppData\Roaming\Microsoft\Protect')) {
            [pscustomobject]@{UserSID=$sid; Path=Join-Path ([Environment]::ExpandEnvironmentVariables($profile)) $relative}
        }
    }
}
Capture 'password-management-policy' {
    $paths=@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS','HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd')
    foreach ($path in $paths) {
        if (!(Test-Path $path)) { [pscustomobject]@{Path=$path;Present=$false}; continue }
        $p=Get-ItemProperty $path
        [pscustomobject]@{Path=$path;Present=$true;BackupDirectory=$p.BackupDirectory;PasswordAgeDays=$p.PasswordAgeDays;PasswordLength=$p.PasswordLength;PasswordComplexity=$p.PasswordComplexity;ADPasswordEncryptionEnabled=$p.ADPasswordEncryptionEnabled;PostAuthenticationActions=$p.PostAuthenticationActions;AdmPwdEnabled=$p.AdmPwdEnabled}
    }
}
Capture 'password-management-events' {
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-LAPS/Operational'; Id=@(10018,10020,10021)} -MaxEvents 100 | Select-Object Id,TimeCreated,Level
}
Capture 'user-installer-policy' {
    Get-ChildItem Registry::HKEY_USERS | Where-Object PSChildName -Match '^S-1-5-21-[0-9-]+$' | ForEach-Object {
        $path=$_.PSPath+'\Software\Policies\Microsoft\Windows\Installer'
        if (Test-Path $path) { $p=Get-ItemProperty $path; [pscustomobject]@{UserSID=$_.PSChildName;AlwaysInstallElevated=$p.AlwaysInstallElevated} }
    }
}
