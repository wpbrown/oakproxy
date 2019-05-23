using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.AzureAD.UI;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.HostFiltering;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
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
        private readonly IConfiguration _configuration;
        private readonly OAKProxyOptions _options;

        public Startup(IConfiguration configuration)
        {
            _configuration = configuration;
            _options = _configuration.GetSection("OAKProxy").Get<OAKProxyOptions>();
        }

        public void ConfigureServices(IServiceCollection services)
        {
            services.Configure<OAKProxyOptions>(_configuration.GetSection("OAKProxy"));

            ConfigureAuthentication(services);
            ConfigureAuthorization(services);
            ConfigureProxy(services);

            services.AddHealthChecks();
        }

        private void ConfigureAuthentication(IServiceCollection services)
        {
            services.AddScoped<IAuthenticationHandlerProvider, FilteredAuthenticationHandlerProvider>();

            var authBuilder = services.AddAuthentication();
            foreach (var application in _options.ProxiedApplications)
            {
                var schemes = ProxyAuthComponents.GetAuthSchemes(application);

                if (application.HasPathMode(PathAuthOptions.AuthMode.Api))
                {
                    authBuilder.AddAzureADBearer(
                        scheme: schemes.ApiName,
                        jwtBearerScheme: schemes.JwtBearerName,
                        configureOptions: options =>
                        {
                            _configuration.Bind("AzureAD", options);
                            options.ClientId = application.ClientId;
                        });
                }

                if (application.HasPathMode(PathAuthOptions.AuthMode.Web))
                {
                    authBuilder.AddAzureAD(
                        scheme: schemes.WebName,
                        openIdConnectScheme: schemes.OpenIdName,
                        cookieScheme: schemes.CookieName,
                        displayName: schemes.DisplayName,
                        configureOptions: options =>
                        {
                            _configuration.Bind("AzureAD", options);
                            options.ClientId = application.ClientId;
                        });
                }
            }
                
            services.ConfigureAll<JwtBearerOptions>(options =>
            {
                var application = _options.ProxiedApplications.Single(app => app.ClientId == options.Audience);
                options.TokenValidationParameters.ValidAudiences = new string[] { application.AppIdUri };
                options.TokenValidationParameters.AuthenticationType = ProxyAuthComponents.ApiAuth;
                options.TokenValidationParameters.RoleClaimType = AzureADClaims.Roles;
                options.TokenValidationParameters.NameClaimTypeRetriever = (token, _) =>
                {
                    var jwtToken = (JwtSecurityToken)token;
                    return jwtToken.Claims.Any(c => c.ValueType == AzureADClaims.UserPrincipalName) ?
                        AzureADClaims.UserPrincipalName : AzureADClaims.ObjectId;
                };

                options.SecurityTokenValidators.Clear();
                options.SecurityTokenValidators.Add(new JwtSecurityTokenHandler
                {
                    MapInboundClaims = false
                });

            });

            services.ConfigureAll<OpenIdConnectOptions>(options =>
            {
                options.ClaimActions.Remove("aud");
                options.TokenValidationParameters.AuthenticationType = ProxyAuthComponents.WebAuth;
                options.TokenValidationParameters.RoleClaimType = AzureADClaims.Roles;
                options.TokenValidationParameters.NameClaimType = AzureADClaims.UserPrincipalName;

                options.SecurityTokenValidator = new JwtSecurityTokenHandler
                {
                    MapInboundClaims = false
                };
            });

            services.ConfigureAll<CookieAuthenticationOptions>(options =>
            {
                options.AccessDeniedPath = "/.oakproxy/accessdenied";
            });
        }

        private void ConfigureAuthorization(IServiceCollection services)
        {
            services.AddTransient<IPolicyEvaluator, StatusPolicyEvaluator>();
            services.AddAuthorization(options => CreateAuthorizationPolicies(options, _options));
        }

        private static void CreateAuthorizationPolicies(AuthorizationOptions options, OAKProxyOptions oakOptions)
        {
            foreach (var application in oakOptions.ProxiedApplications)
            {
                var schemes = ProxyAuthComponents.GetAuthSchemes(application);

                if (application.HasPathMode(PathAuthOptions.AuthMode.Api))
                {
                    options.AddPolicy(ProxyAuthComponents.GetApiPolicyName(application), builder =>
                    {
                        var apiSchemes = new List<string>() { schemes.ApiName };
                        if (application.ApiAllowWebSession)
                            apiSchemes.Add(schemes.CookieName);

                        builder.AddAuthenticationSchemes(apiSchemes.ToArray())
                            .RequireAuthenticatedUser()
                            .AddRequirements(new AuthorizationClaimsRequirement(application.WebRequireRoleClaim));
                    });
                }

                if (application.HasPathMode(PathAuthOptions.AuthMode.Web))
                {
                    options.AddPolicy(ProxyAuthComponents.GetWebPolicyName(application), builder =>
                    {
                        builder.AddAuthenticationSchemes(schemes.WebName)
                            .RequireAuthenticatedUser();

                        if (application.WebRequireRoleClaim)
                            builder.RequireRole(ProxyAuthComponents.WebUserRole);
                    });
                }
            }
        }

        private void ConfigureProxy(IServiceCollection services)
        {
            services.AddScoped<IProxyApplicationService, ProxyApplicationService>();

            if (_options.BehindReverseProxy)
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
                options.AllowedHosts = _options.ProxiedApplications.Select(x => x.Host.Value).ToArray();
            });

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

        public void Configure(IApplicationBuilder app, IOptions<OAKProxyOptions> options)
        {
            app.UseHealthChecks("/.oakproxy/health");
            app.UseStatusCodePages(Errors.StatusPageAsync);
            app.UseExceptionHandler(new ExceptionHandlerOptions { ExceptionHandler = Errors.Handle });

            if (options.Value.BehindReverseProxy)
            {
                app.UseForwardedHeaders();
            }

            app.UseHostFiltering();
            app.UseAuthentication();
            app.Map("/.oakproxy", ConfigureMetaPath);
            app.UsePolicyEvaluation();
            app.RunProxy();
        }

        private static readonly PathString _authenticatedPath = new PathString("/auth");

        private void ConfigureMetaPath(IApplicationBuilder app)
        {
            app.UseWhen(
                context => context.Request.Path.StartsWithSegments(_authenticatedPath), 
                a => a.UsePolicyEvaluation());
            app.RunProxyMeta();
        }
    }
}
