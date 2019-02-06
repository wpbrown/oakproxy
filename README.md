![img](docs/images/title.svg)
<hr/>

OAKProxy is an OAuth2 to Kerberos gateway. Incoming connections are authorized with JWT bearer tokens. A kerberos token is retrieved for the user identified by the JWT and used to forward the request to a backend. Backend applications require zero modification as the proxied request will look just like one coming from a domain-joined client.

![img](docs/images/highlevel.svg)

AD domain authentication is often a roadblock when enterprises attempt to start modernizing a legacy system using the [strangler pattern](https://docs.microsoft.com/en-us/azure/architecture/patterns/strangler). The strangler pattern advocates incrementally peeling functionality out of the legacy system in to a new environment. However, legacy and modern authentication do not mix. A service running in Azure with an Azure AD security principal has no trust in the AD domain. OAKProxy is a gateway that allows the AD domain to trust Azure AD identity. With OAKProxy, modern amd legacy authentication can coexist in a single system.

OAKProxy is for bearer authentication (e.g. REST API calls) only. If you are looking for a browser session aware (OIDC to Kerberos) proxy, see [Azure AD Application Proxy](https://docs.microsoft.com/en-us/azure/active-directory/manage-apps/application-proxy).

## Features

* A single instance can proxy any number of applications.
* Stateless. Can be deployed in a highly-available configuration.
* Translate user identies (token acquired via auth code grant) to domain users.
* Translate application identities (token acquired via client credential grant) to domain users.
* Each AD domain application gets a unique identity with roles and scopes in Azure AD.

# Documentation

- [Security](#security)
  - [Mitigation](#mitigation)
- [OAuth2](#oauth2)
  - [User Impersonation](#user-impersonation)
  - [Service Accounts](#service-accounts)
- [Identity Translation](#identity-translation)
  - [Users](#users)
  - [Applications](#applications)
- [Deployment Scenarios](#deployment-scenarios)
  - [High Availability](#high-availability)
- [Prerequisites](#prerequisites)
  - [Kerberos](#kerberos)
  - [Service Account](#service-account)
    - [Configure a gMSA for Constrained Delegation](#configure-a-gmsa-for-constrained-delegation)
- [Installation](#installation)
- [Uninstallation](#uninstallation)
- [Application Configuration](#application-configuration)
  - [Register Applications in Azure AD](#register-applications-in-azure-ad)
    - [Optional Claims for Alternate Logon ID](#optional-claims-for-alternate-logon-id)
  - [Configuration File](#configuration-file)
    - [ProxiedApplication Object](#proxiedapplication-object)
    - [ServicePrincipalMapping Object](#serviceprincipalmapping-object)
    - [Complete Example](#complete-example)
- [Troubleshooting](#troubleshooting)
- [Roadmap](#roadmap)

# Security

Because the service account that runs OAKProxy is trusted for delegation, the account and the machine that runs the service should be considered part of your [Tier 0 identity infrastructure](https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/securing-privileged-access-reference-material). 

## Mitigation

The service account should always be configured for *constrained* delegation. This limits OAKProxy's ability to impersonate users only to a list of services maintained by a privileged user such as a Domain Admin.

Using a gMSA is recommended to limit the potential for abuse of abuse of the privileged service account. This applies to all privileged service accounts, not just OAKProxy.

The service account requires no special rights (e.g. SeTcbPrivilege, SeImpersonatePrivilege) on the host machine which limits exposure. The service account only has the ability to impersonate to the specific service principals defined in the constrained delegation configuration in AD.

# OAuth2

Each application proxied by OAKProxy is represented by a unique application registration in Azure AD. Client applications consume proxied APIs like any other API protected by modern authentication. There is no indication to the consumer that this is a proxied API.

There is a prototypical app registration for proxied apps. The apps must have exactly one scope defined: `user_impersonation` and one role which applications are eligble for: `app_impersonation`.

![img](docs/images/aadrep.svg)

## User Impersonation

An application can acquire a JWT token that will allow it to call a proxied API which in the end reaches the backend as the domain identity of the user represented by the token. This is done via the auth code grant flow. Either the user or an admin of the user's tenant must first consent the `user_impersonation` scope to the application.

## Service Accounts

An application can acquire a JWT token that will allow it to call a proxied API which in the end reaches the backend as the domain identity of an account configured in OAKProxy. This is done via the client credential grant. Either the owner of the API or an admin of the API's tenant must first grant the `app_impersonation` role to the application.

# Identity Translation

There are 2 Azure AD identity types that OAKProxy will translate to domain identities: user principals and application service principals.

## Users

In the simplest scenario, the domain is being synchronized to Azure AD by Azure AD Connect. The Azure AD UPN is equivilant to the AD DS UPN. The `upn` claim of the incoming access JWT token will simply be looked up in AD DS.

Not all environments use the AD DS UPN to populate the Azure AD UPN (e.g. AD `mail` attribute is sometimes used for the cloud UPN). This is known as [alternate login ID](https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/operations/configuring-alternate-login-id). In this scenario you must configure [optional claims](#optional-claims-for-alternate-logon-id) for each of your applications. This will cause Azure AD to include the `onprem_sid` claim in the access token. OAKProxy will use this claim to look up the user in AD DS by their SID. 

## Applications

In hybrid environments, AD DS service accounts have no sychronization relationship with Azure AD service principals. In OAKProxy you can establish the relationship by manually mapping Azure AD service principals to AD DS accounts. In addition to users, the AD DS account can be a gMSA or Computer, but they must be assigned a userPrincipalName. 

# Deployment Scenarios

OAKProxy can be deployed on-premise or in Azure. The server can and should be deployed behind a firewall or application gateway.

The server can be run on an account or host with highly constrained or no outbound internet access. It only communicates outbound to Azure AD metadata endpoints (periodically) and the backends that you configure. If OAKProxy has no outbound intenet access you must provide Azure AD metadata to the application manually via configuration and you are responsible for keeping it up to date.

## High Availability

OAKProxy is a stateless proxy. Any number of instances can be load-balanced.

# Prerequisites

The only prerequisites for the software installation are what is [required for .NET Core](https://docs.microsoft.com/en-us/dotnet/core/windows-prerequisites). For Windows Server 2016 or higher this means nothing additional is required.

## Kerberos

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

## Service Account

A user account, MSA, or gMSA must already created and configured to run the OAKProxy service. The service account must be trusted for "any protocol" constrained delegation to any of the backend services you intend to proxy. gMSA is the recommended service account type if your environment supports it.

### Configure a gMSA for Constrained Delegation

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

# Installation

1. Extract the release .zip on a local drive.
2. Open an administrator PowerShell in the extracted directory.
3. `Import-Module .\OAKProxy.psm1` .\
   If you get an execution policy error you need to adjust temporarily `Set-ExecutionPolicy Bypass -Scope Process` . 
4. Configure the service by editing `appsettings.json`.
5. Run `Install-OAKProxy` and supply the credential that the service will run with. This will install and start the service. If the credential is for a gMSA, leave the password blank.

# Uninstallation

1. Open an administrator PowerShell in the installation directory.
2. `Import-Module .\OAKProxy.psm1` .
3. Run `Uninstall-OAKProxy` to stop and delete the service.
4. Delete installation directory.

# Application Configuration

Each application proxied by OAKProxy has a unique application registration in Azure AD.

## Register Applications in Azure AD

Applications can be registered like any API application using the portal ([old](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-v1-add-azure-ad-app), [new](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app)), PowerShell, or the CLI. Whatever method you choose, you must configure:
1. A `user_impersonation` OAuth2 scope.
2. An `app_impersonation` application role.
3. An Application ID URI.

Any further customization is allowed and optional. Below is a PowerShell example to configure a minimal application registration:

```PowerShell
$role = [Microsoft.Open.AzureAD.Model.AppRole]@{ 
  AllowedMemberTypes = @("Application"); 
  Description = "Allow the application to access Contoso HR API as a service account.";
  DisplayName = "Access Contoso HR API";
  Value = "app_impersonation";
  Id = New-Guid;
  IsEnabled = $true
}

$app = New-AzureADApplication -DisplayName "Contoso HR API" `
  -IdentifierUris "http://contoso.com/api/HR" `
  -AppRoles @($role)

New-AzureADServicePrincipal -AppId $app.AppId
```

If you use the `New-AzureADApplication` PowerShell command or the _old_ portal UI the default `user_impersonation` scope is created for you. Otherwise you need to add it to the [application manifest](https://docs.microsoft.com/en-us/azure/active-directory/develop/reference-app-manifest) (you must generate a new UUID for the role):
```json
"oauth2Permissions": [
    {
      "adminConsentDescription": "Allow the application to access Contoso HR API on behalf of the signed-in user.",
      "adminConsentDisplayName": "Access Contoso HR API",
      "id": "12345678-1234-1234-1234-123456789012",
      "isEnabled": true,
      "type": "User",
      "userConsentDescription": "Allow the application to access Contoso HR API on your behalf.",
      "userConsentDisplayName": "Access Contoso HR API",
      "value": "user_impersonation"
    }
  ]
```

### Optional Claims for Alternate Logon ID

When you use alternate logon ID, you must enable the on-premise SAM ID claim so OAKProxy can look up on the AD DS user. Add the following section to the [application manifest](https://docs.microsoft.com/en-us/azure/active-directory/develop/reference-app-manifest):
```json
"optionalClaims": {
    "accessToken": [
      {
        "name": "onprem_sid",
        "source": null,
        "essential": true,
        "additionalProperties": []
      }
    ]
  }
```

## Configuration File

All configuration is done with the `appsettings.json` file in the installation directory.

Name | Default | Description
--- | --- | ---
**AzureAD.Instance** | *required* | The URL for the Azure cloud (typically `https://login.microsoftonline.com/`).
**AzureAD.TenantId** | *required*  | The UUID for your Azure AD tenant.
**OAKProxy.ProxiedApplications** | *required* | An array of ProxiedApplication JSON objects. At least 1 application must be configured.
OAKProxy.SidMatching | `Never` | Users are matched to AD DS users only by UPN by default (`Never`). To switch matching on SID, first ensure the optional claim is configured and then set to `Only`. To match on SID if the claim is present and fallback to UPN match otherwise, set to `First`. This is useful for mixed environments where some users are mastered in AD DS and some in Azure AD. When using `First`, if the SID claim is present but no match is found, this is an error, no fallback will occur.
OAKProxy.ServicePrincipalMappings | *optional* | An array of ServicePrincipalMapping objects. Applications connecting that do not have a mapping specified will be denied access even if they have the app_impersonation role.
Host.Urls | `http://*` | Specifies the interfaces and ports to listen on. Production deployments must use HTTPS.


### ProxiedApplication Object

Name | Default | Description
--- | --- | ---
**Audience** | *required* | The identifier URI or "App ID URI" of the application registration in Azure AD.
**Destination** | *required*  | The URL for the backend application being proxied.

### ServicePrincipalMapping Object

Name | Default | Description
--- | --- | ---
**ObjectId** | *required* | The object ID of the Azure AD service principal (_not_ the application object ID or app ID).
**UserPrincipalName** | *required*  | The AD DS UPN of the user, computer, or service account to impersonate.

### Complete Example

An example `appsetting.json` configured to proxy 2 applications for Contoso corp.

```json
{
    "Logging": {
        "LogLevel": {
            "Default": "Warning",
            "OAKProxy": "Information"
        }
    },
    "AzureAD": {
        "Instance": "https://login.microsoftonline.com/",
        "TenantId": "84a3c4da-5d91-4223-abb7-2a9e961bb726"
    },
    "OAKProxy": {
        "ProxiedApplications": [
            {
                "Audience": "http://contoso.com/api/HR",
                "Destination": "http://hr.corp.contoso.com/"
            },
            {
                "Audience": "http://contoso.com/api/billing",
                "Destination": "http://nycbillweb001/"
            }
        ],
        "ServicePrincipalMappings": [
            {
                "ObjectId": "b40771c1-d24a-4cf4-92a8-7a7c78ac4ae7",
                "UserPrincipalName": "xsazrbill@corp.contoso.com"
            }
        ],
        "SidMatching": "None"
    },
    "Host": {
        "Urls": "http://*"
    },
    "AllowedHosts": "*"
}
```

# Troubleshooting

You can run OAKProxy as a console application by simply runnings `.\OAKProxy.exe` on the command line from the installation directory. When running as a service, logs are written to 'Application' Windows Event Log with the source `OAKProxy`.

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

# Roadmap

See the [roadmap project](https://github.com/wpbrown/oakproxy/projects/2). 
