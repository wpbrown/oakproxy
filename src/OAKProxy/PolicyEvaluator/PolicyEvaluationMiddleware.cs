using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Authorization;
using Microsoft.ApplicationInsights.DataContracts;
using System.Linq;
using OAKProxy.Proxy;
using System.Net;

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

        public async Task Invoke(HttpContext context, IProxyApplicationService applicationService, IPolicyEvaluator policyEvaluator)
        {
            var activeApplication = applicationService.GetActiveApplication();
            var mode = context.Request.PathBase == ProxyMetaEndpoints.PathBase ? PathAuthOptions.AuthMode.Web :
                activeApplication.GetPathMode(context.Request.Path);
            if (!mode.HasValue)
            {
                context.Response.StatusCode = (int)HttpStatusCode.Forbidden;
                context.SetErrorDetail(Errors.Code.UnconfiguredPath, "Path has no authentication method configured.");
                return;
            }

            if (mode == PathAuthOptions.AuthMode.None)
            {
                await _next(context);
                return;
            }

            var policyName = mode == PathAuthOptions.AuthMode.Web ?
                ProxyAuthComponents.GetWebPolicyName(activeApplication) :
                ProxyAuthComponents.GetApiPolicyName(activeApplication);
            var policy = await _policyProvider.GetPolicyAsync(policyName);

            var authenticateResult = await policyEvaluator.AuthenticateAsync(policy, context);
            var authorizeResult = await policyEvaluator.AuthorizeAsync(policy, authenticateResult, context, null);

            var telemetry = context.Features.Get<RequestTelemetry>();
            if (telemetry != null && authenticateResult.Succeeded)
            {
                telemetry.Context.User.Id = context.User.Identity.Name;
            }

            if (authorizeResult.Challenged)
            {
                await context.ChallengeAsync(policy.AuthenticationSchemes.First());
            }
            else if (authorizeResult.Forbidden)
            {
                await context.ForbidAsync(policy.AuthenticationSchemes.First());
            }
            else
            {
                await _next(context);
            }
        }
    }
}