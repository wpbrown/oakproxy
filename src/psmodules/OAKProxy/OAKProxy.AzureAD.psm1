function New-OAKProxyADApplication {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]
        $DisplayName,

        [Parameter(Mandatory, ParameterSetName = 'Api')]
        [Parameter(Mandatory, ParameterSetName = 'ApiAndWeb')]
        [switch]
        $Api,

        [Parameter(Mandatory, ParameterSetName = 'Api')]
        [Parameter(Mandatory, ParameterSetName = 'ApiAndWeb')]
        [string]
        $ApplicationIdUri,

        [Parameter(Mandatory, ParameterSetName = 'Web')]
        [Parameter(Mandatory, ParameterSetName = 'ApiAndWeb')]
        [switch]
        $Web,

        [Parameter(ParameterSetName = 'Web')]
        [Parameter(ParameterSetName = 'ApiAndWeb')]
        [switch]
        $DisableImplicitIdToken,

        [Parameter(Mandatory, ParameterSetName = 'Web')]
        [Parameter(Mandatory, ParameterSetName = 'ApiAndWeb')]
        [string]
        $HomePageUrl,

        [Parameter()]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.Core.IAzureContextContainer]
        $DefaultProfile
    )

    $context = Get-Context $DefaultProfile
    $header = Get-AuthorizationHeader $context

    $body = @{
        'availableToOtherTenants'        = $false
        'displayName'                    = $DisplayName
        'identifierUris'                 = @()
        'appRoles'                       = @(
            @{
                'allowedMemberTypes' = @('Application')
                'description'        = 'A client application service principal can call the API with a transitioned identity.'
                'displayName'        = 'Service Account Impersonation'
                'value'              = 'app_impersonation'
                'id'                 = (New-Guid).Guid
            },
            @{
                'allowedMemberTypes' = @('User')
                'description'        = 'A user can sign in to the web application with a transitioned identity when authorization is enforced by the proxy.'
                'displayName'        = 'Web User'
                'value'              = 'user_web'
                'id'                 = (New-Guid).Guid
            },
            @{
                'allowedMemberTypes' = @('User')
                'description'        = 'A user can use other applications to call the API with a transitioned identity when authorization is enforced by the proxy.'
                'displayName'        = 'API User'
                'value'              = 'user_api'
                'id'                 = (New-Guid).Guid
            }
        )
        'optionalClaims'                 = @{
            'idToken'     = @(
                @{
                    'name'      = 'sid'
                    'essential' = $false
                },
                @{
                    'name'      = 'onprem_sid'
                    'essential' = $false
                },
                @{
                    'name'                 = 'upn'
                    'essential'            = $true
                    'additionalProperties' = @('include_externally_authenticated_upn')
                }
            )
            'accessToken' = @(
                @{
                    'name'      = 'onprem_sid'
                    'essential' = $false
                },
                @{
                    'name'                 = 'upn'
                    'essential'            = $true
                    'additionalProperties' = @('include_externally_authenticated_upn')
                }
            )
        }
        'requiredResourceAccess'         = @(
            @{
                "resourceAppId"  = "00000003-0000-0000-c000-000000000000"
                "resourceAccess" = @(
                    @{
                        "id"   = "e1fe6dd8-ba31-4d61-89e7-88639da4683d"
                        "type" = "Scope"
                    }
                )
            }
        )
        'oauth2AllowIdTokenImplicitFlow' = !$DisableImplicitIdToken
    }

    if ($Api) {
        Write-Verbose 'Setting up API mode...'
        $body['identifierUris'] = @($ApplicationIdUri)
    }   

    if ($Web) {
        Write-Verbose 'Setting up Web mode...'
        $body['homepage'] = $HomePageUrl
        $homePageBase = ([uri]$HomePageUrl).GetLeftPart('Authority')
        $body['logoutUrl'] = "$homePageBase/.oakproxy/logout"
        $body['replyUrls'] = @("$homePageBase/.oakproxy/login")
    }   

    $application = Invoke-RestMethod -Headers @{'Authorization' = $header } -Method 'Post' `
        -Uri "https://graph.windows.net/$($context.Tenant.Id)/applications?api-version=1.6" `
        -Body ($body | ConvertTo-Json -Depth 10) -ContentType "application/json"

    if ($DisableImplicitIdToken) {
        $message = "Implicit id_token flow is disabled. `"Web`" mode will not work for this application until a credential is added to the application and configured in OAKProxy.`n`n" +
        "To add a secret or certificate use New-AzADAppCredential -ApplicationId '$($application.appId)' ...`n"
        Write-Warning -Message $message
    }
    
    $application | Select-Object -Property 'objectId', 'appId'
}

function Get-Context {
    param(
        [Parameter()]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.Core.IAzureContextContainer]
        $DefaultProfile
    )

    if ($DefaultProfile) {
        return $DefaultProfile.DefaultContext
    }
    else {
        return [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile.DefaultContext
    }
}

function Get-AuthorizationHeader {
    param(
        [Parameter(Mandatory)]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.IAzureContext]
        $Context
    )

    $token = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($context.Account, $context.Environment, $context.Tenant.Id, $null, 'Never', $null, $context.Environment.GraphEndpointResourceId)
    $callback = {
        param($type, $value)
        $header = "$type $value"
        Set-Variable -Scope 1 -Name 'header' -Value $header
    }
    $token.AuthorizeRequest($callback)
    return $header
}