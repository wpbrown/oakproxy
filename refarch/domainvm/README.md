# Domain-joined VM Reference Architecture

This reference architecture is ideal for enterprises that need to proxy one or more Windows Integrated Authentication applications. This reference architecture is a 100% infrastructure as code model. The servers do not require any backup because the entire resource group can be destroyed and recreated at will with this reference architecture.

It can be deployed for internal corporate network use, or presented to the internet with an Azure Application Gateway.

# Prerequisites

* A VNet on the corporate network routing domain (i.e. a "VDC spoke" or a VNet with a VPN or ExpressRoute gateway).
* An AD DS OU to place the server computer objects.
* An AD DS security group to contain the server computer objects.
* An AD DS account that can join VMs in the OU and update the group.
* An AD DS domain with a [KDS Root Key](https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/create-the-key-distribution-services-kds-root-key) (to support the use of a gMSA).
* A gMSA account that will run the OAKProxy service on the domain VMs.
* List of the SPNs for the Kerberos applications that OAKProxy will front.

## Create the AD DS structure

First create the OU and group. Ideally the parent OU has minimal Group Policy linked, but at least has policy to enforce highly restricted access. Customize as appropriate for your domain naming and placement policies.

```powershell
$OUName = 'OAKProxy Servers'
$groupName = 'azeastoak-all'
$groupDescription = 'OAKProxy Azure East Cluster'
$parentOU = 'OU=Privileged Servers,DC=corp,DC=contoso,DC=com'

$group = New-ADGroup -Name $groupName -Description $groupDescription -GroupScope Global -Path $parentOU
$ou = New-ADOrganizationalUnit -Name $OUName -Path $parentOU -PassThru
```

The account used in the template to join the new VMs to the domain needs write access to these pre-staged computer objects. It is recommended to create a least privilege user account for this.

```powershell
$accountName = 'xsoakproxymanage'
$parentOU = 'OU=Privileged Users,DC=corp,DC=contoso,DC=com'
$credential = Get-Credential -UserName $accountName -Message 'Provide the password...'
$user New-ADUser -Name $accountName -AccountNotDelegated $true -PasswordNeverExpires $true `
    -Path $parentOU -UserPrincipalName 'xsoakproxymanage@corp.contoso.com' `
    -Enabled $true -AccountPassword $credential.Password -PassThru

$acl = Get-Acl -Path "AD:\$($ou.DistinguishedName)"
$securityIdentifier = [System.Security.Principal.SecurityIdentifier]::new($user.SID)
$fullControlComputers = [System.DirectoryServices.ActiveDirectoryAccessRule]::new()
$createDeleteComputers = [System.DirectoryServices.ActiveDirectoryAccessRule]::new()
$manageGroupMembers = [System.DirectoryServices.ActiveDirectoryAccessRule]::new()
$acl.AddAccessRule($ace1)
$acl.AddAccessRule($ace2)
$acl.AddAccessRule($ace3)
Set-Acl -Path "AD:\$($ou.DistinguishedName)" -AclObject $acl
```

## Create the gMSA

Create the gMSA that will run the OAKProxy service and assign it to be used on the cluster. You will need the SPNs of the services that will receive connections via OAKProxy for this step.

```powershell
$groupName = 'azeastoak-all'
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

On going operations and maintenance of the service should follow a 

## Constrained Delegation ACL

The maintenance of the domain records will likely be integrated with an existing DevOps/IaC process for configuration of AD DS. In large organizations, this process may be owned by a completely different team than the one maintaining OAKProxy infrastructure.

