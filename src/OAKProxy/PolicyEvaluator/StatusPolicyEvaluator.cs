using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Http;

namespace OAKProxy.PolicyEvaluator
{
    public class StatusPolicyEvaluator : IPolicyEvaluator
    {
        private readonly IAuthorizationService _authorization;

        public StatusPolicyEvaluator(IAuthorizationService authorization)
        {
            _authorization = authorization;
        }

        public async Task<AuthenticateResult> AuthenticateAsync(AuthorizationPolicy policy, HttpContext context)
        {
            if (policy.AuthenticationSchemes == null || policy.AuthenticationSchemes.Count == 0)
            {
                throw new Exception("Authenticating a policy with no schemes specified is not supported.");
            }

            AuthenticateResult result = null;
            foreach (var scheme in policy.AuthenticationSchemes)
            {
                result = await context.AuthenticateAsync(scheme);
                if (result != null && result.Succeeded)
                {
                    break;
                }
            }

            if (result != null && result.Succeeded)
            {
                context.User = result.Principal;
                context.AuthenticationTicket(result.Ticket);
                return result;
            }
            else
            {
                context.User = new ClaimsPrincipal(new ClaimsIdentity());
                return AuthenticateResult.NoResult();
            }
        }


        public async Task<PolicyAuthorizationResult> AuthorizeAsync(AuthorizationPolicy policy, AuthenticateResult authenticationResult, HttpContext context, object resource)
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

            //if (result.Failure?.FailedRequirements.Any(x => x is AuthorizationClaimsRequirement) ?? false)
            //{
            //    context.SetErrorDetail(Errors.Code.NoAuthorizationClaims, "Authorization claim is missing from the authenticated token.");
            //}
            
            // If authentication was successful, return forbidden, otherwise challenge
            return (authenticationResult.Succeeded)
                ? PolicyAuthorizationResult.Forbid()
                : PolicyAuthorizationResult.Challenge();
        }
    }
}