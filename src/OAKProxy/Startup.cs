using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.AzureAD.UI;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.HostFiltering;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using OAKProxy.PolicyEvaluator;
using OAKProxy.Proxy;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace OAKProxy
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        private IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            services.Configure<OAKProxyOptions>(Configuration.GetSection("OAKProxy"));

            ConfigureAuthentication(services);
            ConfigureAuthorization(services);
            ConfigureProxy(services);

            services.AddHealthChecks();
        }

        private void ConfigureAuthentication(IServiceCollection services)
        {
            services.AddScoped<IAuthenticationHandlerProvider, FilteredAuthenticationHandlerProvider>();

            var authBuilder = services.AddAuthentication();

            var oakOptions = Configuration.GetSection("OAKProxy").Get<OAKProxyOptions>();
            foreach (var app in oakOptions.ProxiedApplications)
            {
                authBuilder.AddAzureAD(
                    $"{app.Name}.{AzureADDefaults.AuthenticationScheme}",
                    $"{app.Name}.{AzureADDefaults.OpenIdScheme}",
                    $"{app.Name}.{AzureADDefaults.CookieScheme}",
                    $"{app.Name}.{AzureADDefaults.DisplayName}", 
                    options => {
                        Configuration.Bind("AzureAD", options);
                        options.ClientId = app.ClientId;
                    });
            }
                
            services.ConfigureAll<OpenIdConnectOptions>(options =>
            {
                options.ClaimActions.Remove("aud");
                options.SecurityTokenValidator = new JwtSecurityTokenHandler
                {
                    MapInboundClaims = false
                };
            });
        }

        private void ConfigureAuthorization(IServiceCollection services)
        {
            var oakOptions = Configuration.GetSection("OAKProxy").Get<OAKProxyOptions>();

            // Require valid Azure AD bearer token with user_impersonation scope or app_impersonation role.
            services.AddAuthorization(options =>
            {
                options.AddPolicy("Bearer",
                    builder => builder.AddAuthenticationSchemes(AzureADDefaults.BearerAuthenticationScheme)
                                        .RequireAuthenticatedUser()
                                        .AddRequirements(new AuthorizationClaimsRequirement()));

                foreach (var app in oakOptions.ProxiedApplications)
                {
                    options.AddPolicy(app.Host + ".OpenID",
                        builder => builder.AddAuthenticationSchemes($"{app.Name}.{AzureADDefaults.AuthenticationScheme}")
                                            .RequireAuthenticatedUser());
                }
            });

            services.Add(ServiceDescriptor.Transient<IPolicyEvaluator, StatusPolicyEvaluator>());
            services.AddAuthorizationPolicyEvaluator();
        }

        private void ConfigureProxy(IServiceCollection services)
        {
            var oakOptions = Configuration.GetSection("OAKProxy").Get<OAKProxyOptions>();
            if (oakOptions.BehindReverseProxy)
            {
                services.Configure<ForwardedHeadersOptions>(options =>
                {
                    options.ForwardedHeaders = ForwardedHeaders.All;
                    options.ForwardedHostHeaderName = "X-Original-Host";
                    options.KnownProxies.Clear();
                    options.KnownNetworks.Clear();
                });
            }
            
            services.Configure<HostFilteringOptions>(options =>
            {
                options.AllowedHosts = oakOptions.ProxiedApplications.Select(x => x.Host).ToArray();
            });

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

        public void Configure(IApplicationBuilder app, IHostingEnvironment env, HttpForwarder forwarder, IOptions<OAKProxyOptions> options, ProxyService proxy)
        {
            app.UseHealthChecks("/.oakproxy/health");

            if (options.Value.BehindReverseProxy)
            {
                app.UseForwardedHeaders();
            }
            app.UseHostFiltering();
            app.UseStatusCodePages(Errors.StatusPageAsync);
            app.UseExceptionHandler(new ExceptionHandlerOptions { ExceptionHandler = Errors.Handle });
            app.UseAuthentication();

            app.UsePolicyEvaluation();
            app.Use(async (context, next) => {
                if (context.Request.Path == "/.oakproxy/auth/logout")
                {
                    string application = proxy.GetActiveApplication(context.Request.Host.Host);

                    await context.SignOutAsync($"{application}.{AzureADDefaults.CookieScheme}");
                    await context.SignOutAsync($"{application}.{AzureADDefaults.OpenIdScheme}");
                }
                else
                {
                    await next.Invoke();
                }
            });
            app.RunProxy();
        }
    }
}
