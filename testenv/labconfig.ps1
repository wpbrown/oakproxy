Configuration CreateDomain
{
    param
    (
        [Parameter(Mandatory)]
        [PSCredential]$AdminPassword,

        [Parameter(Mandatory)]
        [PSCredential]$UserPassword,

        [Parameter(Mandatory)]
        [string]$DomainName,

        [Parameter(Mandatory)]
        [string]$DomainNetbiosName
    )

    Import-DscResource -ModuleName xActiveDirectory, PSDesiredStateConfiguration

    Node localhost
    {
        LocalConfigurationManager {
            ActionAfterReboot = 'ContinueConfiguration'
            ConfigurationMode = 'ApplyAndAutoCorrect'
            RebootNodeIfNeeded = $true
        }

        WindowsFeatureSet Services {
            Name = @('DNS', 'AD-Domain-Services')
            Ensure = 'Present'
            IncludeAllSubFeature = $true
        }

        WindowsFeatureSet Tools {
            Name = @('RSAT-AD-Tools', 'RSAT-DHCP', 'RSAT-DNS-Server', 'GPMC')
            Ensure = 'Present'
            IncludeAllSubFeature = $true
        }

        xADDomain LabDomain {
            DomainName = $DomainName
            DomainNetbiosName = $DomainNetbiosName
            DomainAdministratorCredential = $AdminPassword
            SafemodeAdministratorPassword = $AdminPassword
            DatabasePath = 'C:\Adds\NTDS'
            LogPath = 'C:\Adds\NTDS'
            SysvolPath = 'C:\Adds\SYSVOL'
            DependsOn = '[WindowsFeatureSet]Services'
        }

        xADUser xoda {
            DomainName = $DomainName
            UserName = 'xoda'
            Password = $AdminPassword
            PasswordNeverExpires = $true
            DependsOn = '[xADDomain]LabDomain'
        }

        xADUser user1 {
            DomainName = $DomainName
            UserName = 'user1'
            Password = $UserPassword
            PasswordNeverExpires = $true
            DependsOn = '[xADDomain]LabDomain'
        }

        xADUser user2 {
            DomainName = $DomainName
            UserName = 'user2'
            Password = $UserPassword
            PasswordNeverExpires = $true
            DependsOn = '[xADDomain]LabDomain'
        }

        xADUser xsokprox {
            DomainName = $DomainName
            UserName = 'xsokprox'
            Password = $UserPassword
            PasswordNeverExpires = $true
            DependsOn = '[xADDomain]LabDomain'
        }
    }
}

Configuration JoinClient
{
    param
    (
        [Parameter(Mandatory)]
        [PSCredential]$AdminPassword,

        [Parameter(Mandatory)]
        [string]$DomainName
    )

    Import-DscResource -ModuleName ComputerManagementDSC, PSDesiredStateConfiguration

    Node localhost
    {
        LocalConfigurationManager {
            ActionAfterReboot = 'ContinueConfiguration'
            ConfigurationMode = 'ApplyAndAutoCorrect'
            RebootNodeIfNeeded = $true
        }

        Computer JoinComputer {
            Name = 'localhost'
            DomainName = $DomainName
            Credential = $AdminPassword
        }

        Group RdpUsers {
            GroupName = 'Remote Desktop Users'
            MembersToInclude = @("$DomainName\user1", "$DomainName\user2")
        }

        foreach ($mode in @('SOFTWARE', 'SOFTWARE\WOW6432Node')) {
            foreach ($config in @('Domains', 'EscDomains')) {
                Registry "LocalZone-$($mode.replace('\','-'))-$config" {
                    Key = "HKEY_LOCAL_MACHINE\$mode\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\$config\$DomainName"
                    ValueName = '*'
                    Force = $true
                    ValueData = '1'
                    ValueType = 'Dword'
                }
            }
        }
    }
}

Configuration JoinProxy
{
    param
    (
        [Parameter(Mandatory)]
        [PSCredential]$AdminPassword,

        [Parameter(Mandatory)]
        [string]$DomainName
    )

    Import-DscResource -ModuleName ComputerManagementDSC, PSDesiredStateConfiguration

    Node localhost
    {
        LocalConfigurationManager {
            ActionAfterReboot = 'ContinueConfiguration'
            ConfigurationMode = 'ApplyAndAutoCorrect'
            RebootNodeIfNeeded = $true
        }

        Computer JoinComputer {
            Name = 'localhost'
            DomainName = $DomainName
            Credential = $AdminPassword
        }

        foreach ($mode in @('SOFTWARE', 'SOFTWARE\WOW6432Node')) {
            foreach ($config in @('Domains', 'EscDomains')) {
                Registry "LocalZone-$($mode.replace('\','-'))-$config" {
                    Key = "HKEY_LOCAL_MACHINE\$mode\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\$config\$DomainName"
                    ValueName = '*'
                    Force = $true
                    ValueData = '1'
                    ValueType = 'Dword'
                }
            }
        }
    }
}

Configuration AppServ
{
    param
    (
        [Parameter(Mandatory)]
        [PSCredential]$AdminPassword,

        [Parameter(Mandatory)]
        [string]$DomainName,

        [Parameter(Mandatory)]
        [string]$AppUrl
    )

    Import-DscResource -ModuleName xSmbShare, xSystemSecurity, xDnsServer, xActiveDirectory, xWebAdministration, ComputerManagementDSC, PSDesiredStateConfiguration, xPSDesiredStateConfiguration

    $localIp = (Get-NetIPConfiguration).IPv4Address.IPAddress | Select-Object -First 1

    Node localhost
    {
        LocalConfigurationManager {
            ActionAfterReboot = 'ContinueConfiguration'
            ConfigurationMode = 'ApplyAndAutoCorrect'
            RebootNodeIfNeeded = $true
        }

        WindowsFeatureSet Services {
            Name = @('Web-Webserver', 'Web-Asp-Net45', 'Web-Windows-Auth', 'FS-FileServer')
            Ensure = 'Present'
        }

        WindowsFeatureSet Tools {
            Name = @('Web-Mgmt-Console', 'Web-Scripting-Tools', 'RSAT-AD-PowerShell', 'RSAT-DNS-Server')
            Ensure = 'Present'
        }

        Computer JoinComputer {
            Name = 'localhost'
            DomainName = $DomainName
            Credential = $AdminPassword
        }

        # Workaround .NET not using Tls12 by default. Breaks xRemoteFile request to Github.
        # https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/393
        Script EnableTLS12 {
            SetScript = {
                [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol.toString() + ', ' + [Net.SecurityProtocolType]::Tls12
            }
            TestScript = {
               return ([Net.ServicePointManager]::SecurityProtocol -match 'Tls12')
            }
            GetScript = {
                return @{
                    Result = ([Net.ServicePointManager]::SecurityProtocol -match 'Tls12')
                }
            }
        }

        xRemoteFile DownloadTestApp {
            Uri = $AppUrl
            DestinationPath = 'C:\Packages\testapp.zip'
            MatchSource = $false
            DependsOn = '[Script]EnableTLS12'
        }

        Archive UnpackTestApp {
            Path = 'C:\Packages\testapp.zip'
            Destination = 'C:\inetpub\testapp'
            DependsOn = '[xRemoteFile]DownloadTestApp'
        }

        xWebsite TestAppSite {
            Ensure = 'Present'
            Name = 'testapp'
            State = 'Started'
            PhysicalPath = 'C:\inetpub\testapp'
            AuthenticationInfo = MSFT_xWebAuthenticationInformation {
                Anonymous = $false
                Basic = $false
                Digest = $false
                Windows = $true
            }
            BindingInfo = @(
                MSFT_xWebBindingInformation {
                    Protocol = 'http'
                    Hostname = "testapp.$DomainName"
                }
                MSFT_xWebBindingInformation {
                    Protocol = 'http'
                    Hostname = 'testapp'
                }
            )
            DependsOn = '[WindowsFeatureSet]Services', '[Archive]UnpackTestApp'
        }

        xADServicePrincipalName TestAppSpnShort {
            ServicePrincipalName = 'http/testapp'
            Account = 'appserv$'
            DependsOn = '[WindowsFeatureSet]Tools', '[Computer]JoinComputer'
            PsDscRunAsCredential = $AdminPassword
        }

        xADServicePrincipalName TestAppSpnLong {
            ServicePrincipalName = "http/testapp.$DomainName"
            Account = 'appserv$'
            DependsOn = '[WindowsFeatureSet]Tools', '[Computer]JoinComputer'
            PsDscRunAsCredential = $AdminPassword
        }

        xDnsRecord TestAppDnsRecord {
            Name = 'testapp'
            Zone = $DomainName
            DnsServer = $DomainName
            Target = $localIp
            Type = 'ARecord'
            Ensure = 'Present'
            PsDscRunAsCredential = $AdminPassword
            DependsOn = '[WindowsFeatureSet]Tools'
        }

        File LabDir {
            DestinationPath = 'C:\shared'
            Type = 'Directory'
        }

        File ScratchDir {
            DestinationPath = 'D:\shared'
            Type = 'Directory'
        }

        xSmbShare LabFileshare {
            Name = 'lab'
            Path = 'C:\shared'
            FullAccess = 'Authenticated Users'
            DependsOn = '[WindowsFeatureSet]Services', '[File]LabDir'
        }

        xSmbShare ScratchFileshare {
            Name = 'scratch'
            Path = 'D:\shared'
            FullAccess = 'Authenticated Users'
            DependsOn = '[WindowsFeatureSet]Services', '[File]ScratchDir'
        }

        xFileSystemAccessRule LabDirAcl {
            Path = 'C:\shared'
            Identity = 'Authenticated Users'
            Rights = 'Modify'
            DependsOn = '[File]LabDir'
        }

        xFileSystemAccessRule ScratchDirAcl {
            Path = 'D:\shared'
            Identity = 'Authenticated Users'
            Rights = 'Modify'
            DependsOn = '[File]ScratchDir'
        }
    }
}
