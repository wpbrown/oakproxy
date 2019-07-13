# Domain-joined VM Reference Architecture

This reference architecture is ideal for enterprises that need to proxy one or more Windows Integrated Authentication applications. This reference architecture is a 100% infrastructure as code model. The servers do not require any backup because the entire resource group can be destroyed and recreated at will with this reference architecture.

The default deployment is highly available inside a data center. It makes use of 3 fault domains with LRS storage and 3 VMs. By enabling the availability zones option the entire deployment can be zone redundant across 3 data centers in a region.

## Networking Options

The reference architecture can be deployed for internal corporate network access only (internal mode), presented to the internet with an Azure Application Gateway (external mode), or both.

Internal mode will deploy an internal network load balancer and expose an HTTPS endpoint on a private IP in the corporate network. OAKProxy must be configured to listen on an HTTPS endpoint in addition to HTTP.

External mode will deploy an Azure Application Gateway and expose an HTTPS endpoint on a public IP on the internet. OAKProxy should be configured to listen on an HTTP endpoint.

# Prerequisites

* A VNet on the corporate network routing domain (i.e. a "VDC spoke" or a VNet with a VPN or ExpressRoute gateway).
* An AD DS OU to place the server computer objects.
* An AD DS security group to contain the server computer objects.
* An AD DS account that can join VMs in the OU and update the group.
* An AD DS domain with a [KDS Root Key](https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/create-the-key-distribution-services-kds-root-key) (to support the use of a gMSA).
* A gMSA account that will run the OAKProxy service on the domain VMs.
* A list of the SPNs for the Kerberos applications that OAKProxy will front.

## External Mode

* A publicly trusted certificate for all of the hostnames this deployment will handle. 
* A DNS zone where CNAME records for each proxied application can be created.

To simplify management and adding new applications, a wildcard certificate is recommended.

## Create the AD DS structure

First create the OU and security group. Ideally the OU has minimal Group Policy linked, but at least has policy to enforce highly restricted access to these VMs. Customize as appropriate for your domain managment policies.

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

They should add code or a declaration in their source repository for the assignment of SPNs that can be updated in a deployment pipeline. PowerShell DSC example:

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