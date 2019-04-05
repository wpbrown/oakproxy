using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Http;

namespace OAKProxy.PolicyEvaluator
{
    public class StatusPolicyEvaluator : Microsoft.AspNetCore.Authorization.Policy.PolicyEvaluator
    {
        private readonly IAuthorizationService _authorization;

        public StatusPolicyEvaluator(IAuthorizationService authorization) :
            base(authorization)
        {
            _authorization = authorization;
        }

        public override async Task<PolicyAuthorizationResult> AuthorizeAsync(AuthorizationPolicy policy, AuthenticateResult authenticationResult, HttpContext context, object resource)
        {
            if (policy == null)
            {
                throw new ArgumentNullException(nameof(policy));
            }

            var result = await _authorization.AuthorizeAsync(context.User, resource, policy);
            if (result.Succeeded)
            {
                return PolicyAuthorizationResult.Success();
            }

            if (result.Failure?.FailedRequirements.Any(x => x is AuthorizationClaimsRequirement) ?? false)
            {
                context.SetErrorDetail(Errors.Code.NoAuthorizationClaims, "Authorization claim is missing from the authenticated token.");
            }
            
            // If authentication was successful, return forbidden, otherwise challenge
            return (authenticationResult.Succeeded)
                ? PolicyAuthorizationResult.Forbid()
                : PolicyAuthorizationResult.Challenge();
        }
    }
}