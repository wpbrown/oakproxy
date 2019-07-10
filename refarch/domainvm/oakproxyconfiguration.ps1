Configuration OakproxyConfiguration
{
    param
    (
        [Parameter(Mandatory)]
        [PSCredential]$DomainJoinCredential,

        [Parameter(Mandatory)]
        [string]$GmsaName,

        [Parameter(Mandatory)]
        [string]$DomainName,

        [Parameter(Mandatory)]
        [string]$DomainOrganizationalUnit,

        [Parameter(Mandatory)]
        [string]$DomainGroupName,

        [Parameter(Mandatory)]
        [string]$OakproxyPackageUrl,

        [Parameter(Mandatory)]
        [string]$OakproxyConfigurationUrl,

        [Parameter()]
        [string]$ArtifactsSasToken
    )

    Import-DscResource -ModuleName xActiveDirectory
    Import-DscResource -ModuleName PSDscResources
    Import-DscResource -ModuleName xPSDesiredStateConfiguration
    Import-DscResource -ModuleName ComputerManagementDSC
    Import-DscResource -ModuleName NetworkingDsc

    if ($ArtifactsSasToken) {
        $OakproxyPackageUrl = $OakproxyPackageUrl + $ArtifactsSasToken
        $OakproxyConfigurationUrl = $OakproxyConfigurationUrl + $ArtifactsSasToken
    }
    
    Node localhost
    {
        LocalConfigurationManager {
            ActionAfterReboot = 'ContinueConfiguration'
            ConfigurationMode = 'ApplyAndAutoCorrect'
            RebootNodeIfNeeded = $true
        }

        # Join VM to the domain
        Computer JoinComputer {
            Name = 'localhost'
            DomainName = $DomainName
            Credential = $DomainJoinCredential
            JoinOU = $DomainOrganizationalUnit
        }

        # Install prerequisites of the xActiveDirectory module
        WindowsFeatureSet Tools {
            Name = @('RSAT-AD-PowerShell')
            Ensure = 'Present'
            IncludeAllSubFeature = $true
        }

        # Add Self to the gMSA access group
        xADGroup OakproxyGmsaServers {
            GroupName = $DomainGroupName
            Category = 'Security'
            Ensure = 'Present'
            MembersToInclude = @("$env:COMPUTERNAME$")
            Credential = $DomainJoinCredential
            DependsOn = '[WindowsFeatureSet]Tools', '[Computer]JoinComputer'
        }

        # Test and cache the gMSA account
        Script VerifyGmsa {
            GetScript = {
                return @{
                    Result = (Test-ADServiceAccount -Identity $using:GmsaName)
                }
            }
            TestScript = {
                return (Test-ADServiceAccount -Identity $using:GmsaName)
            }
            SetScript = {
                # Ensure our computer accounts Kerberos ticket has the gMSA group membership
                # by forcing it to retrieve new tickets.
                klist.exe purge
                Install-ADServiceAccount -Identity $using:GmsaName
            }
            DependsOn = '[xADGroup]OakproxyGmsaServers'
        }

        # Disable Server Manager on logon
        Registry DisableServerManager {
            Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Server\ServerManager'
            ValueName = 'DoNotOpenAtLogon'
            Force = $true
            ValueData = '1'
            ValueType = 'Dword'
        }

        # Create log source
        Script LogSource {
            GetScript = {
                return @{
                    Result = ([System.Diagnostics.EventLog]::SourceExists('OAKProxy'))
                }
            }
            TestScript = {
                return ([System.Diagnostics.EventLog]::SourceExists('OAKProxy'))
            }
            SetScript = {
                New-EventLog -LogName 'Application' -Source 'OAKProxy'
            }
        }

        # Ask xRemoteFile to speak TLS1.2 for GitHub compatibility
        Script EnableTls12 {
            GetScript = {
                return @{
                    Result = ([Net.ServicePointManager]::SecurityProtocol -match 'Tls12')
                }
            }
            TestScript = {
                return ([Net.ServicePointManager]::SecurityProtocol -match 'Tls12')
            }
            SetScript = {
                [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol.toString() + ', ' + [Net.SecurityProtocolType]::Tls12
            }
        }

        $installationRoot = 'C:\Packages\Applications\OAKProxy'
        $packageVersion = ([Uri]$OakproxyPackageUrl).Segments[-2].TrimEnd('/')
        $downloadToPath = "$installationRoot\$packageVersion.zip"

        # Download the installation package
        xRemoteFile DownloadInstaller {
            Uri = $OakproxyPackageUrl
            DestinationPath = $downloadToPath
            MatchSource = $false
            DependsOn = '[Script]EnableTls12'
        }
    
        # Extract the installation package
        Archive UnpackTestApp {
            Path = $downloadToPath
            Destination = "$installationRoot\$packageVersion"
            DependsOn = '[xRemoteFile]DownloadInstaller'
        }

        # Download the configuration file
        # Will be replaced with Azure Configuration Service when it is GA.
        xRemoteFile DownloadConfiguration {
            Uri = $OakproxyConfigurationUrl
            DestinationPath = 'C:\ProgramData\oakproxy\oakproxy.yml'
            MatchSource = $true
            DependsOn = '[Script]EnableTls12'
        }

        # Configure the OAKProxy service
        xService OAKProxy {
            Name = 'oakproxy'
            Ensure = 'Present'
            Path = "$installationRoot\$packageVersion\oakproxy.exe -service"
            DisplayName = 'OAKProxy'
            Description = 'OAKProxy authenticating reverse-proxy.'
            GroupManagedServiceAccount = "$DomainName\$GmsaName$"
            StartupType = 'Automatic'
            State = 'Running'
            DependsOn = '[Archive]UnpackTestApp', '[Script]LogSource', '[Script]VerifyGmsa', '[xRemoteFile]DownloadConfiguration'
        }

        # Open Ports for the Service
        Firewall OpenPorts
        {
            Name = 'OAKProxy HTTP/HTTPS'
            Ensure = 'Present'
            Enabled = 'True'
            Profile  = 'Domain', 'Private'
            Program = "$installationRoot\$packageVersion\oakproxy.exe"
            Direction = 'InBound'
            LocalPort = '80', '443'
            Protocol = 'TCP'
            DependsOn = '[Archive]UnpackTestApp'
        }
    }
}
