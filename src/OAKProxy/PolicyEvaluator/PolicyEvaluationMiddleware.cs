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
        private readonly string _policyName;
        private readonly IAuthorizationPolicyProvider _policyProvider;

        public PolicyEvaluationMiddleware(RequestDelegate next, IAuthorizationPolicyProvider policyProvider) :
             this(next, policyProvider, null)
        {
        }

        public PolicyEvaluationMiddleware(RequestDelegate next, IAuthorizationPolicyProvider policyProvider, string policyName)
        {
            _next = next ?? throw new ArgumentNullException(nameof(next));
            _policyName = policyName;
            _policyProvider = policyProvider;
        }

        public async Task Invoke(HttpContext context)
        {
            var policy = _policyName != null ? 
                await _policyProvider.GetPolicyAsync(_policyName) : 
                await _policyProvider.GetDefaultPolicyAsync();
            var policyEvaluator = context.RequestServices.GetRequiredService<IPolicyEvaluator>();
            var authenticateResult = await policyEvaluator.AuthenticateAsync(policy, context);
            var authorizeResult = await policyEvaluator.AuthorizeAsync(policy, authenticateResult, context, null);

            var telemetry = context.Features.Get<RequestTelemetry>();
            if (telemetry != null)
            {
                telemetry.Context.User.Id = context.User.Claims.FirstOrDefault(c => c.Type == "upn")?.Value ??
                                            context.User.Claims.FirstOrDefault(c => c.Type == "oid").Value;
            }

            if (authorizeResult.Challenged)
            {
                await context.ChallengeAsync();
            }
            else if (authorizeResult.Forbidden)
            {
                await context.ForbidAsync();
            }
            else
            {
                await _next(context);
            }
        }
    }
}