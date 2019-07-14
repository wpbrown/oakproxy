$VerbosePreference = 'Continue'

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
        [string]$KeyBlobContainerUrl,
        
        [Parameter(Mandatory)]
        [string]$OakproxyPackageUrl,

        [Parameter(Mandatory)]
        [string]$OakproxyConfigurationUrl,

        [Parameter()]
        [string]$ArtifactsSasToken,

        [Parameter()]
        [string]$HttpsCertificateData,

        [Parameter()]
        [PSCredential]$HttpsCertificateCredential
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

        # Configure Key Management to use Blob Storage and DPAPING
        File KeyStoreConfig {
            DestinationPath = 'C:\ProgramData\oakproxy\config\Server__KeyManagement__StoreToBlobContainer'
            Contents = "$KeyBlobContainerUrl/keydata.blob"
            Force = $true
        }

        File KeyEncryptionConfig {
            DestinationPath = 'C:\ProgramData\oakproxy\config\Server__KeyManagement__ProtectWithDpapiNg__UseSelfRule'
            Contents = 'true'
            Force = $true
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

        $oakproxyServiceDependencies = @('[Archive]UnpackTestApp', '[Script]LogSource', '[Script]VerifyGmsa', '[xRemoteFile]DownloadConfiguration',
            '[File]KeyStoreConfig', '[File]KeyEncryptionConfig')

        if ($HttpsCertificateData) {
            # Install the certificate during compilation of the configuration. See [Note1] at the bottom.
            $data = [Convert]::FromBase64String($HttpsCertificateData)
            $cert = [Security.Cryptography.X509Certificates.X509Certificate2]::new($data, $HttpsCertificateCredential.Password, 'EphemeralKeySet')
            $certThumbprint = $cert.Thumbprint
            $storeCert = Get-ChildItem -Path "Cert:\LocalMachine\My\$($cert.Thumbprint)" -ErrorAction Ignore
            if ($null -eq $storeCert) {
                Write-Verbose "Certificate '$certThumbprint' not found. Installing..."
                $cert = [Security.Cryptography.X509Certificates.X509Certificate2]::new($data, $HttpsCertificateCredential.Password, 'MachineKeySet, PersistKeySet')
                $certStore = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', 'LocalMachine')
                $certStore.Open('ReadWrite')
                $certStore.Add($cert)
                $certStore.Close()
            } else {
                Write-Verbose "Certificate '$certThumbprint' was found."
            }

            $oakproxyServiceDependencies += '[Script]UpdateCertificateKeyAcl'
            
            # Update the certificate ACL
            Script UpdateCertificateKeyAcl {
                GetScript = {
                    $cert = Get-ChildItem -Path "Cert:\LocalMachine\My\$($using:certThumbprint)" -ErrorAction Ignore
                    $access = $cert.PrivateKey.CspKeyContainerInfo.CryptoKeySecurity.Access.IdentityReference.Value | Where-Object { $_.EndsWith("\$using:GmsaName$") }
                    return @{
                        Result = if ($access) { $access } else { 'Missing' }
                    }
                }
                TestScript = {
                    $state = [scriptblock]::Create($GetScript).Invoke()
                    return ($state[0]['Result'] -ne 'Missing')
                }
                SetScript = {
                    $cert = Get-ChildItem -Path "Cert:\LocalMachine\My\$($using:certThumbprint)" -ErrorAction Ignore
                    $containerInfo = $cert.PrivateKey.CspKeyContainerInfo
                    $csp = [Security.Cryptography.CspParameters]::new($containerInfo.ProviderType, $containerInfo.ProviderName, $containerInfo.KeyContainerName)
                    $csp.Flags = 'UseExistingKey', 'UseMachineKeyStore'
                    $csp.CryptoKeySecurity = $containerInfo.CryptoKeySecurity
                    $csp.KeyNumber = $containerInfo.KeyNumber
                    $rule = [Security.AccessControl.CryptoKeyAccessRule]::new("$using:GmsaName$", 'GenericRead', 'Allow')
                    $csp.CryptoKeySecurity.AddAccessRule($rule)
                    $rsa = [Security.Cryptography.RSACryptoServiceProvider]::new($csp)
                    $rsa.Dispose()
                }
                DependsOn = '[Computer]JoinComputer'
            }
        } else {
            Write-Verbose 'No certificate data provided.'
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
            DependsOn = $oakproxyServiceDependencies
        }
    }
}

# [Note1]
# If we use CertificateDSC to install the cert, it will use Import-PfxCertificate, which will use CNG to store the private key. 
# There are no .NET APIs for this and thus we can't change the private key ACL through .NET or Powershell once it's installed.
# There is a clunky way to retrieve the key container name with PInvokes and then we update the ACL via the file system, but doing
# all this inside a Script resource is just too much. See the how below:
#  https://www.sysadmins.lv/blog-en/retrieve-cng-key-container-name-and-unique-name.aspx
#  https://stackoverflow.com/questions/17185429/how-to-grant-permission-to-private-key-from-powershell/22146915
#  
# We can't install the script with a script resource securly because SecureStrings can't be passed in to Script Resource script
# blocks. Ultimately I decide since the future of DSC will continue investing in compilation on the target node*, it's not that 
# bad to cheat and install the cert at compilation time. This means DSC regular evaluations will not restore the cert if it is 
# removed. We still do update the ACL with a DSC Resource because it depends on being domain joined and looking up the gMSA's 
# SID.
#
# * https://devblogs.microsoft.com/powershell/azure-policy-guest-configuration-client/