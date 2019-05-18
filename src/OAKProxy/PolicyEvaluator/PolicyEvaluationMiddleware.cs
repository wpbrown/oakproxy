using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Authorization;
using Microsoft.ApplicationInsights.DataContracts;
using System.Linq;

namespace OAKProxy.PolicyEvaluator
{
    public class PolicyEvaluationMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IAuthorizationPolicyProvider _policyProvider;

        public PolicyEvaluationMiddleware(RequestDelegate next, IAuthorizationPolicyProvider policyProvider)
        {
            _next = next ?? throw new ArgumentNullException(nameof(next));
            _policyProvider = policyProvider;
        }

        public async Task Invoke(HttpContext context)
        {
            var policyName = context.Request.Host + ".OpenID";
            var policy = await _policyProvider.GetPolicyAsync(policyName);
            var policyEvaluator = context.RequestServices.GetRequiredService<IPolicyEvaluator>();
            var authenticateResult = await policyEvaluator.AuthenticateAsync(policy, context);
            var authorizeResult = await policyEvaluator.AuthorizeAsync(policy, authenticateResult, context, null);

            var telemetry = context.Features.Get<RequestTelemetry>();
            if (telemetry != null && authenticateResult.Succeeded)
            {
                telemetry.Context.User.Id = context.User.Claims.FirstOrDefault(c => c.Type == "upn")?.Value ??
                                            context.User.Claims.FirstOrDefault(c => c.Type == "oid").Value;
            }

            if (authorizeResult.Challenged)
            {
                await context.ChallengeAsync(policy.AuthenticationSchemes.Single());
            }
            else if (authorizeResult.Forbidden)
            {
                await context.ForbidAsync(policy.AuthenticationSchemes.Single());
            }
            else
            {
                await _next(context);
            }
        }
    }
}