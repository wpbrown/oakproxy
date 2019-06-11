using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Http;
using OAKProxy.Proxy;

namespace OAKProxy.PolicyEvaluator
{
    public class AuthorizationClaimsRequirement : AssertionRequirement
    {
        public AuthorizationClaimsRequirement(bool webRequireRoleClaim) :
            base(context => {
                if (context.User.Identity.AuthenticationType == ProxyAuthComponents.WebAuth)
                {
                    return !webRequireRoleClaim || context.User.IsInRole(ProxyAuthComponents.WebUserRole);
                }
                
                if (context.User.Identity.AuthenticationType == ProxyAuthComponents.ApiAuth)
                {
                    if (context.User.HasClaim("apptype", "Confidential") &&
                        context.User.HasClaim(AzureADClaims.Scope, ProxyAuthComponents.ApiAppRole)) // AD FS application
                    {
                        return true;
                    }

                    if (context.User.IsInRole(ProxyAuthComponents.ApiAppRole))
                    {
                        return context.User.HasClaim(c => c.Type == AzureADClaims.ApplicationAuthType && Int32.Parse(c.Value) > 0);
                    }
                    return context.User.HasClaim(AzureADClaims.Scope, ProxyAuthComponents.ApiUserScope);
                }

                return false;
             })
        {
        }
    }
}