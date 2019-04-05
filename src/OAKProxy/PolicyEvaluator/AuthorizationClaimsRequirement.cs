using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Http;

namespace OAKProxy.PolicyEvaluator
{
    public class AuthorizationClaimsRequirement : AssertionRequirement
    {
        private const string AzureADScopeClaimType = "scp";
        private const string AzureADRoleClaimType = "roles";
        private const string AzureADAuthTypeClaimType = "appidacr";

        public AuthorizationClaimsRequirement() :
            base(context =>
                context.User.HasClaim(AzureADScopeClaimType, "user_impersonation") ||
                (context.User.HasClaim(AzureADRoleClaimType, "app_impersonation") &&
                 context.User.HasClaim(c => c.Type == AzureADAuthTypeClaimType && Int32.Parse(c.Value) > 0)))
        {
        }
    }
}