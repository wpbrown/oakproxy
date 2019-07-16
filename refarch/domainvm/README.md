# Domain-joined VM Reference Architecture

This reference architecture is ideal for enterprises that need to enable modern authentication for one or more Windows Integrated Authentication applications (WIA). This architecture also supports all other authentication methods supported by OAKProxy, but it may be overkill if you don't need the Kerberos (WIA) authentication option.

This reference architecture is a 100% infrastructure as code model. All of the VMs use ephemeral disks. As such, they do not require any backup. The entire resource group can be destroyed and recreated from the ARM template.

![img](../../docs/images/refarchdomvm.svg)

## High Availability

The default deployment is highly available across 3 fault domains in a single data center. By enabling the `availabilityZones` option in the template the entire deployment can be zone redundant across 3 data centers in a region.

If you need redundancy across multiple Azure regions, deploy this template to multiple regions. The regions can be run behind shared host names using Azure Traffic Manager.

**Notice**: The artifact storage is a *runtime* dependency of the deployment. Whenever VMs are rebuilt or the scale set is scaled up, artifacts are pulled from the deployment blob storage. _If_ you use the `availabilityZones` option, your artifact storage account must also be a ZRS SKU for your deployment to be zone redundant. Key Vault is _not_ a runtime dependency. There are no sustained refences to Key Vault outside of deployment time.

## Networking Options

The reference architecture can be deployed for internal corporate network access only (internal mode), presented to the internet with an Azure Application Gateway (external mode), or both.

External mode will deploy an Azure Application Gateway and expose an HTTPS endpoint on a public IP on the internet. OAKProxy should be configured to listen on an HTTP endpoint.

Internal mode will deploy an internal network load balancer and expose an HTTPS endpoint on a private IP in the corporate network. OAKProxy must be configured to listen on an HTTPS endpoint in addition to HTTP.

![img](../../docs/images/refarchdomvmpriv.svg)

Internal mode uses 2 Standard Load Balancers. This is due to a requirement of _Standard_ Internal Load Balancers: a separate External Load Balancer is required for egress traffic to the internet. Egress traffic to the internet is only to facilitate access to Azure AD metadata endpoints and Azure blob storage. All direct outbound internet access can be removed using service endpoints and NVAs and then the External Load Balancer is not required. This is beyond the scope of this reference architecture.

# Prerequisites

Most large enterprises will already have processes in place to provide these prerequisites. In case you have no pre-existing process or need more detail, some example administrative commands are provided in this section.

* A VNet on the corporate network routing domain (i.e. a "[VDC spoke](https://docs.microsoft.com/en-us/azure/architecture/vdc/)" or a VNet with a VPN or ExpressRoute gateway).
* An AD DS OU to place the server computer objects.
* An AD DS security group to contain the server computer objects.
* An AD DS account that can join VMs in the OU and update the group.
* An AD DS domain with a [KDS Root Key](https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/create-the-key-distribution-services-kds-root-key) (to support the use of a gMSA).
* A gMSA account that will run the OAKProxy service on the domain VMs.
* A list of the SPNs for the Kerberos applications that OAKProxy will provide authentication services.
* A certificate trusted by your clients or publicly for all of the hostnames this deployment will handle. 
* A DNS zone where CNAME records for each proxied application can be created.

To simplify management and adding new applications, a wildcard certificate is recommended.

## Create the AD DS structure

First create the OU and security group. Ideally the OU has minimal Group Policy linked, but at least has policy to enforce highly restricted access to these VMs. Customize as appropriate for your domain management policies.

```powershell
$OUName = 'OAKProxy Servers'
$groupName = 'azoakservers'
$groupDescription = 'OAKProxy Cluster Servers'
$parentServerOU = 'OU=Privileged Servers,DC=corp,DC=contoso,DC=com'

$ou = New-ADOrganizationalUnit -Name $OUName -Path $parentServerOU -PassThru
$group = New-ADGroup -Name $groupName -Description $groupDescription -GroupScope Global -Path $ou.DistinguishedName
```

The account used with the ARM deployment to join the new VMs to the domain needs write access to the OU and security group. It is recommended to create a least privilege user account for this. The script below will create this user and give it permission to manage computer objects and group members within the new OU.

```powershell
$serverOU = 'OU=OAKProxy Servers,OU=Privileged Servers,DC=corp,DC=contoso,DC=com'
$accountName = 'xsoakproxymanage'
$parentUserOU = 'OU=Privileged Users,DC=corp,DC=contoso,DC=com'
$accountUpn = "$accountName@corp.contoso.com"
$credential = Get-Credential -UserName $accountName -Message 'Provide the password...'

$ou = Get-ADOrganizationalUnit -Identity $serverOU
$user = New-ADUser -Name $accountName -AccountNotDelegated $true -PasswordNeverExpires $true `
    -Path $parentUserOU -UserPrincipalName $accountUpn -Enabled $true `
    -AccountPassword $credential.Password -PassThru
$acl = Get-Acl -Path "AD:\$($ou.DistinguishedName)"
$securityIdentifier = [System.Security.Principal.SecurityIdentifier]::new($user.SID)
$schemaContext = (Get-ADRootDSE).SchemaNamingContext
$computerGuid = [System.Guid](Get-ADObject -SearchBase $schemaContext -LDAPFilter '(name=Computer)' -Properties schemaIDGUID).schemaIDGUID
$groupGuid = [System.Guid](Get-ADObject -SearchBase $schemaContext -LDAPFilter '(name=Group)' -Properties schemaIDGUID).schemaIDGUID
$memberGuid = [System.Guid](Get-ADObject -SearchBase $schemaContext -LDAPFilter '(name=Member)' -Properties schemaIDGUID).schemaIDGUID
$accessCreateDeleteChild = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild -bor [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild
$accessReadWriteProperty = [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty -bor [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
$inheritanceDescendents = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
$fullControlComputers = [System.DirectoryServices.ActiveDirectoryAccessRule]::new($securityIdentifier, 'GenericAll', 'Allow', $inheritanceDescendents, $computerGuid)
$createDeleteComputers = [System.DirectoryServices.ActiveDirectoryAccessRule]::new($securityIdentifier, $accessCreateDeleteChild, 'Allow', $computerGuid, 'All')
$manageGroupMembers = [System.DirectoryServices.ActiveDirectoryAccessRule]::new($securityIdentifier, $accessReadWriteProperty, 'Allow', $memberGuid, $inheritanceDescendents, $groupGuid)
$acl.AddAccessRule($fullControlComputers)
$acl.AddAccessRule($createDeleteComputers)
$acl.AddAccessRule($manageGroupMembers)
Set-Acl -Path "AD:\$($ou.DistinguishedName)" -AclObject $acl
```

## Create the gMSA

Create the gMSA that will run the OAKProxy service and assign it to be used on the cluster. You will need the SPNs of the services that will receive connections via OAKProxy for this step.

```powershell
$groupName = 'azoakservers'
$accountName = 'oakproxygmsa'
$accountHostname = "${accountName}.corp.contoso.com"
$proxiedServiceSpns = @('http/billingapp','http/billingapp.corp.contoso.com', 'http/widgetsales.corp.contoso.com')
$group = Get-ADGroup -Identity $groupName
$serviceAccount = New-ADServiceAccount -Name $accountName `
    -PrincipalsAllowedToRetrieveManagedPassword $group `
    -DNSHostName $accountHostname -PassThru `
    -OtherAttributes @{'msDS-AllowedToDelegateTo' = $proxiedServiceSpns}
$serviceAccount | Set-ADAccountControl -TrustedToAuthForDelegation $true
```

## HTTPS Certificate

In both public or private access modes, you must provide a certificate for HTTPS. Modern authentication requires an HTTPS reply URL regardless of whether the application is internal to your network or not. 

In public mode, the certificate _must_ be specified in the `httpsCertificateData` template argument. This certificate will be installed in to the Application Gateway.

In private mode, the certificate _may_ be specified in the template. If the certificate is specified, it will be installed on the VMs and the gMSA account will granted access to use it. If you do not specify a certificate you should configure AD Certificate Services and a certificate autoenrollment GPO for the OAKProxy OU.

In either mode, the certificate is not required to be publicly trusted. You can use your internal certificate authority. Only the devices accessing the OAKProxy service need to trust the certificate. If devices that you do not configure with your CA root certificate access the service, you will need a publicly trusted certificate.

# Deployment

TODO

1. Populate the `parameter.json`.
2. Deploy the `azuredeploy.json`.

# DevOps Integration

On going operations and maintenance of the service should follow a DevOps process. The original deployment process above can be rerun in a pipeline to deploy updates to the service.

## External Dependencies

The maintenance of the AD DS objects will likely be integrated with an existing DevOps/IaC process for configuration of AD DS. In large organizations, this process may be owned by a completely different team than the one maintaining OAKProxy infrastructure.

### Computer Objects

Either the AD DS team or the team responsible for OAKProxy must add a process to their existing automation systems that purges old computer objects from the AD DS directory. The VM scale set will add new objects over time, especially if auto-scaling is enabled. As configured above the `xsoakproxymanage` account would have the privilege needed to delete the computer objects, so an OAKProxy team could automate this, however those responsible for AD DS will likely have more stake excess objects in AD DS so they may want to take responsibility for this process.

```powershell
$InformationPreference = 'Continue'
$oakproxyOU = 'OU=OAKProxy Servers,OU=Privileged Servers,DC=corp,DC=contoso,DC=com'
Connect-AzAccount -Identity # Assumes running in Azure with a managed identity

$hostnames = (Get-AzVmssVM -ResourceGroupName "oakproxy-rg" -VMScaleSetName "oakproxy-vmss").OsProfile.ComputerName
Get-ADComputer -Filter * -SearchBase $oakproxyOU |
    Where-Object { $_.Name -notin $hostnames } | 
    ForEach-Object { Write-Information -MessageData "Deleting $($_.Name)."; $_ } | 
    Remove-ADObject -Recursive -Confirm:$false
```

### Constrained Delegation ACL

The AD DS team should add code or a declaration in their source repository for the assignment of SPNs that can be updated in a deployment pipeline. 

Below is a PowerShell DSC example:

```powershell
# Shared DSC Resources:
Configuration ConstrainedDelegationAnyProtocolTo
{
    param
    (
        [Parameter(Mandatory)]
        [string]$Source,

        [Parameter(Mandatory)]
        [string[]]$TargetSpns
    )

    Script EnableProxyDelegation {
        SetScript = {
            $principal = Get-ADObject -Filter {SAMAccountName -eq $using:Source}
            $principal | Set-ADAccountControl -TrustedToAuthForDelegation $true
            $principal | Set-ADObject -Add @{'msDS-AllowedToDelegateTo' = [string[]]$using:TargetSpns}
        }
        TestScript = {
            $TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000
            $principal = Get-ADObject -Filter {SAMAccountName -eq $using:Source} -Properties 'msDS-AllowedToDelegateTo','userAccountControl'
            return ($null -ne $principal['msDS-AllowedToDelegateTo'].Value -and $null -eq (Compare-Object $principal['msDS-AllowedToDelegateTo'].Value $using:TargetSpns)) -and ($principal['userAccountControl'].Value -band $TRUSTED_TO_AUTH_FOR_DELEGATION)
        }
        GetScript = {
            $principal = Get-ADObject -Filter {SAMAccountName -eq $using:Source} -Properties 'msDS-AllowedToDelegateTo','userAccountControl','samAccountName'
            return @{
                Result = $principal | ConvertTo-Json
            }
        }
    }
}

# Snippet from the AD DS Domain desired state configuration:
$allProdTargetSpns = @('http/billingapp', 'http/billingapp.contoso.com', 'http/widgets.corp.contoso.com')

xADManagedServiceAccount OakproxyGmsaExists {
    ServiceAccountName = 'oakproxygmsa'
    AccountType = 'Group'
    Members = @('azoakservers')
}

ConstrainedDelegationAnyProtocolTo OakproxyGmsaKcdEnabled {
    Source = 'oakproxygmsa$'
    TargetSpns = $allProdTargetSpns
    DependsOn = '[xADManagedServiceAccount]OakproxyGmsaExists'
}
```