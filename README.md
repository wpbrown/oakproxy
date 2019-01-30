# OAKProxy
OAKProxy is an OAuth2 to Kerberos gateway. Incoming connections are authorized with JWT bearer. A kerberos token is retrieved for the user identified by the JWT and used to forward the request to a backend. One instance of OAKProxy can service any number of applications.

![img](docs/images/highlevel.svg)

AD domain authentication is often a roadblock when enterprises attempt to start modernizing a legacy system using the [strangler pattern](https://docs.microsoft.com/en-us/azure/architecture/patterns/strangler). The strangler pattern advocates incrementally peeling functionality out of the legacy system in to a new environment. However, legacy and modern authentication do not mix. A service running in Azure with an Azure AD security principal has no trust in the AD domain. OAKProxy is a gateway that allows the AD domain to trust Azure AD identity. With OAKProxy, modern amd legacy authentication can coexist in a single system.

### Features

* A single instance can proxy any number of applications.
* Stateless. Can be deployed in a highly-available configuration.
* Translate user identies (token acquired via auth code grant) to domain users.
* Translate application identities (token acquired via client credential grant) to domain users.
* Each AD domain application gets a unique identity with roles and scopes in Azure AD.

OAKProxy is for bearer authentication (e.g. REST API calls) only. If you are looking for a browser session aware (OIDC to Kerberos) proxy, see [Azure AD Application Proxy](https://docs.microsoft.com/en-us/azure/active-directory/manage-apps/application-proxy).

## Security

Because the service account that runs OAKProxy is trusted for delegation, the account and the machine that runs the service should be considered part of your [Tier 0 identity infrastructure](https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/securing-privileged-access-reference-material). 

### Mitigation

The service account should always be configured for *constrained* delegation. This limits OAKProxy's ability to impersonate users only to a list of services maintained by a privileged user such as a Domain Admin.

Using a gMSA is recommended to limit the potential for abuse of abuse of the privileged service account. This applies to all privileged service accounts, not just OAKProxy.

### Service Account Rights

There are 2 build types available: `net472` is dependent on .NET Framework 4.7.2 being installed and `core22` is dependent on the .NET Core 2.2 runtime being installed. Due to limitations in .NET Core, the `core22` build requires the service account to have the 'Act as part of the operating system user right on the server hosting OAKProxy. If this is not permissible in your environment, stick with the `net472` build type.

## Deployment Scenarios

TODO

### High Availability

TODO

## Prerequisites

Before installing OAKProxy you must have the appropriate .NET runtime installed. Depending on the build type choose (i.e `net472` or `core22`), [download](https://dotnet.microsoft.com/download) and install the appropriate runtime.

### Kerberos

Kerberos access to your service must already be fully functional on your domain. Check the 'Security' Event Log on the server hosting the service you want to proxy for. Look for Event ID 4624 Logon 'Audit success'. If the details for the event look like below, then at least some clients are not authenticating with Kerberos and you may experience authentication failures with OAKProxy. Ensure that your service has an A record in DNS and the corresponding [SPNs](https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/getting-started-with-group-managed-service-accounts) are configured properly.
```
Detailed Authentication Information:
	Logon Process:		NtLmSsp 
	Authentication Package:	NTLM
	Transited Services:	-
	Package Name (NTLM only):	NTLM V2
	Key Length:		128
```
A proper authentication event looks like below:
```
Detailed Authentication Information:
	Logon Process:		Kerberos
	Authentication Package:	Kerberos
	Transited Services:	-
	Package Name (NTLM only):	-
	Key Length:		0
```

### Service Account

A user account, MSA, or gMSA must already created and configured to run the OAKProxy service. The service account must be trusted for "any protocol" constrained delegation to any of the backend services you intend to proxy. gMSA is the recommended service account type if your environment supports it.

#### Configure a gMSA for Constrained Delegation

Given `oakproxyComputerName` to be the name of the server hosting OAKProxy and `proxiedServiceSpns` to be the SPNs of the services being proxied to, below will create a gMSA to run OAKProxy. This assumes your domain is already [setup for gMSAs](https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/create-the-key-distribution-services-kds-root-key). In a Highly Available deployment of OAKProxy, `$server` would be set to an AD Group that contains all the computer objects hosting OAKProxy, not a single comptuer object.
```PowerShell
$oakproxyComputerName = '...'
$proxiedServiceSpns = @('http/app1','http/app1.corp.contoso.com', '...')
$server = Get-ADComputer $oakproxyComputerName
$gmsa = New-ADServiceAccount -Name 'xgoakproxy' ` 
    -PrincipalsAllowedToRetrieveManagedPassword $server `
    -ServicePrincipalNames 'http/xgoakproxy' `
    -DNSHostName 'xgoakproxy.corp.contoso.com'
$gmsa | Set-ADAccountControl -TrustedToAuthForDelegation $true
$gmsa | Set-ADServiceAccount -Add @{'msDS-AllowedToDelegateTo' = $proxiedServiceSpns}
```

## Installation

1. Extract the release .zip on a local drive.
2. Open an administrator PowerShell in the extracted directory.
3. `Import-Module .\OAKProxy.psm1` .\
   If you get an execution policy error you need to adjust the policy temporarily `Set-ExecutionPolicy Bypass -Scope Process` . 
4. If you are installing the `core22` build type, you must edit the Local Security Policy on the server and grant the service account the *Act as part of the operating system* User Right.
5. Configure the service by editing `appsettings.json`.
6. Run `Install-OAKProxy` to install and start the service.

## Uninstallation

1. Open an administrator PowerShell in the installation directory.
2. `Import-Module .\OAKProxy.psm1` .
3. Run `Uninstall-OAKProxy` to stop and delete the service.
4. Delete installation directory.

## Application Configuration

TODO

### Register Applications in Azure AD

TODO

### Configuration File

TODO

## Troubleshooting

You can run OAKProxy as a console application by simply runnings `.\OAKProxy.exe` on the command line from the installation directory.

Check the 'Security' Event Log on the server hosting the service you are proxying to. Look for Event ID 4624 Logon 'Audit success'. A successful connection via OAKProxy will look like below. In this example `xgoakproxy$` is the gMSA running the OAKProxy service.
```
Detailed Authentication Information:
	Logon Process:		Kerberos
	Authentication Package:	Kerberos
	Transited Services:	
		xgoakproxy$@CORP.CONTOSO.COM
	Package Name (NTLM only):	-
	Key Length:		0
```
Azure AD Application Proxy also uses Kerberos Constrained Delegation in a simliar fashion to OAKProxy. See [their guide](https://docs.microsoft.com/en-us/azure/active-directory/manage-apps/application-proxy-back-end-kerberos-constrained-delegation-how-to) for additional troubleshooting steps.

## Roadmap

Work on a .NET Core version that does not require TCB privilege is in progress. At that the time .NET Framework builds will be deprecated. A Windows Docker image may be available after that.