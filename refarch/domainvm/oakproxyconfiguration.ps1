Configuration OakproxyConfiguration
{
    param
    (
        [Parameter(Mandatory)]
        [PSCredential]$DomainJoinCredential,

        [Parameter(Mandatory)]
        [string]$DomainName,

        [Parameter(Mandatory)]
        [string]$DomainOrganizationalUnit,

        [Parameter(Mandatory)]
        [string]$DomainGroupName
    )

    Import-DscResource -ModuleName xActiveDirectory
    Import-DscResource -ModuleName PSDscResources
    Import-DscResource -ModuleName ComputerManagementDSC
    
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

        # Disable Server Manager on logon
        Registry DisableServerManager {
            Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Server\ServerManager'
            ValueName = 'DoNotOpenAtLogon'
            Force = $true
            ValueData = '1'
            ValueType = 'Dword'
        }
    }
}
