using Microsoft.AspNetCore.Builder;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAKProxy.PolicyEvaluator
{
    public static class AuthAppBuilderExtensions
    {
        public static IApplicationBuilder UsePolicyEvaluation(this IApplicationBuilder app)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            return app.UseMiddleware<PolicyEvaluationMiddleware>();
        }

        public static IApplicationBuilder UsePolicyEvaluation(this IApplicationBuilder app, string policyName)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            return app.UseMiddleware<PolicyEvaluationMiddleware>(policyName);
        }
    }
}
