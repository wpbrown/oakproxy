using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.AzureAD.UI;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OAKProxy.PolicyEvaluator;
using OAKProxy.Proxy;
using System;
using System.Net.Http;

namespace OAKProxy
{
    public class Startup
    {
        private const string AzureADScopeClaimType = "http://schemas.microsoft.com/identity/claims/scope";

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        private IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            ConfigureAuthentication(services);
            ConfigureAuthorization(services);
            ConfigureProxy(services);
        }

        private void ConfigureAuthentication(IServiceCollection services)
        {
            // Add hanlder for Azure AD bearer authentication for REST requests
            services.AddAuthentication(AzureADDefaults.BearerAuthenticationScheme)
                .AddAzureADBearer(options => Configuration.Bind("AzureAD", options));
        }

        private void ConfigureAuthorization(IServiceCollection services)
        {
            // Require valid Azure AD bearer token with user_impersonation scope
            services.AddAuthorization(options =>
            {
                options.AddPolicy("AuthenticatedUser",
                    builder => builder.AddAuthenticationSchemes(AzureADDefaults.BearerAuthenticationScheme)
                                      .RequireAuthenticatedUser()
                                      .RequireClaim(AzureADScopeClaimType, "user_impersonation"));
            });

            services.AddAuthorizationPolicyEvaluator();
        }

        private void ConfigureProxy(IServiceCollection services)
        {
            // Load the oakproxy configuration.
            services.Configure<OAKProxyOptions>(Configuration.GetSection("OAKProxy"));

            // Limit bearer authorization based on proxied applications.
            services.ConfigureOptions<JwtBearerConfiguration>();

            // Register the proxy service.
            services.AddProxy();
            services.AddMemoryCache();

            // Define the forwarder used by the proxy to make make requests.
            services.AddHttpClient<HttpForwarder>().ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
            {
                AllowAutoRedirect = false,
                UseCookies = false,
                UseDefaultCredentials = true,
                UseProxy = false
            });
        }

        public void Configure(IApplicationBuilder app, IHostingEnvironment env, HttpForwarder forwarder)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseHttpsRedirection();
                app.UseStatusCodePages();
            }

            // There is no app.UseAuthentication() because authentication will be handled by the IPolicyEvaluator
            // which is invoked in the PolicyEvaluationMiddleware.

            app.UsePolicyEvaluation(policyName: "AuthenticatedUser");
            app.RunProxy();
        }
    }
}
