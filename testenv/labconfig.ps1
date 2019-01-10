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
        LocalConfigurationManager
        {            
            ActionAfterReboot = 'ContinueConfiguration'            
            ConfigurationMode = 'ApplyAndAutoCorrect'            
            RebootNodeIfNeeded = $true            
        }

        WindowsFeatureSet Services
        { 
            Name = @('DNS', 'AD-Domain-Services')
            Ensure = 'Present'
            IncludeAllSubFeature = $true
        }

        WindowsFeatureSet Tools
        {
            Name = @('RSAT-AD-Tools', 'RSAT-DHCP', 'RSAT-DNS-Server', 'GPMC')
            Ensure = 'Present'
            IncludeAllSubFeature = $true
        }

        xADDomain LabDomain
        {
            DomainName = $DomainName
            DomainNetbiosName = $DomainNetbiosName
            DomainAdministratorCredential = $AdminPassword
            SafemodeAdministratorPassword = $AdminPassword
            DatabasePath = 'C:\Adds\NTDS'
            LogPath = 'C:\Adds\NTDS'
            SysvolPath = 'C:\Adds\SYSVOL'
            DependsOn = '[WindowsFeatureSet]Services'
        }

        xADUser xoda
        {
            DomainName = $DomainName
            UserName = 'xoda'
            Password = $AdminPassword
            PasswordNeverExpires = $true
            DependsOn = '[xADDomain]LabDomain'
        }

        xADUser user1
        {
            DomainName = $DomainName
            UserName = 'user1'
            Password = $UserPassword
            PasswordNeverExpires = $true
            DependsOn = '[xADDomain]LabDomain'
        }

        xADUser user2
        {
            DomainName = $DomainName
            UserName = 'user2'
            Password = $UserPassword
            PasswordNeverExpires = $true
            DependsOn = '[xADDomain]LabDomain'
        }

        xADUser xsokprox
        {
            DomainName = $DomainName
            UserName = 'xsokprox'
            Password = $UserPassword
            PasswordNeverExpires = $true
            DependsOn = '[xADDomain]LabDomain'
        }

        xADUser xsapp
        {
            DomainName = $DomainName
            UserName = 'xsapp'
            Password = $UserPassword
            PasswordNeverExpires = $true
            DependsOn = '[xADDomain]LabDomain'
        }
   }
}

Configuration JoinDomain 
{
    param
    (
        [Parameter(Mandatory)]
        [PSCredential]$AdminPassword,

        [Parameter(Mandatory)]
        [string]$DomainName
    )

    Import-DscResource -ModuleName ComputerManagementDSC

    Node localhost
    {
        LocalConfigurationManager
        {            
            ActionAfterReboot = 'ContinueConfiguration'            
            ConfigurationMode = 'ApplyAndAutoCorrect'            
            RebootNodeIfNeeded = $true            
        }
        
        Computer JoinComputer
        {
            Name = 'localhost'
            DomainName = $DomainName
            Credential = $AdminPassword
        }
   }
}