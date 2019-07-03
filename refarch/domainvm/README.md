# Domain-joined VM Reference Architecture

This reference architecture is ideal for enterprises that need to proxy one or more Windows Integrated Authentication applications. This reference architecture is a 100% infrastructure as code model. The servers do not require any backup because the entire resource group can be destroyed and recreated at will with this reference architecture.

It can be deployed for internal corporate network use, or presented to the internet with an Azure Application Gateway.

# Prerequisites

* A VNet on the corporate network routing domain (i.e. a "VDC spoke" or a VNet with a VPN or ExpressRoute gateway).
* An AD DS account credential that can join VMs to the domain.
* An AD DS domain with a [KDS Root Key](https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/create-the-key-distribution-services-kds-root-key) (to support the use of a gMSA).
* A gMSA account that will run the OAKProxy service on the domain VMs.
* Pre-staged computer objects for the VMs that will be joined to the domain.
* List of the SPNs for the Kerberos applications that OAKProxy will front.

## Create the computer objects

There will be 3 VMs hosting OAKProxy. They use names of your choosing. Customize as appropriate for your domain machine naming and placement policy.

```powershell
$computerNames = @('azeastoak01', 'azeastoak02', 'azeastoak03')
$targetOu = 'OU=Privileged Servers,DC=corp,DC=contoso,DC=com'
$groupName = 'azeastoak-all'
$groupDescription = 'OAKProxy Azure East Cluster'

$computers = $computerNames | ForEach-Object {
    New-ADComputer -Name $_ -Path $targetOu -PassThru
}
$group = New-ADGroup -Name $groupName -Description $groupDescription -GroupScope Global -Path $targetOu -PassThru
$computers | Add-ADPrincipalGroupMembership -MemberOf $group
```

The account used in the template to join the new VMs to the domain needs write access to these pre-staged computer objects.

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