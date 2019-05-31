using Microsoft.AspNetCore.Authentication;
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
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
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
        private readonly ApplicationOptions _options;

        public Startup(IConfiguration configuration, IOptions<ApplicationOptions> options, ILogger<Startup> logger)
        {
            _configuration = configuration;

            try
            {
                _options = options.Value;
            }
            catch (OptionsValidationException e)
            {
                foreach (var failure in e.Failures)
                {
                    logger.LogCritical(failure);
                }
            }
        }

        public void ConfigureServices(IServiceCollection services)
        {
            if (_options is null)
            {
                return;
            }

            if (_options.Server.UseForwardedHeaders)
            {
                services.Configure<ForwardedHeadersOptions>(options =>
                {
                    options.ForwardedHeaders = ForwardedHeaders.All;
                    options.KnownNetworks.Clear();
                    options.KnownProxies.Clear();
                    _configuration.GetSection("Configuration:ForwardedHeaders").Bind(options);
                });
            }

            if (!String.IsNullOrWhiteSpace(_options.Server.ApplicationInsightsKey))
            {
                services.AddApplicationInsightsTelemetry(options =>
                {
                    options.InstrumentationKey = _options.Server.ApplicationInsightsKey;
                    _configuration.GetSection("Configuration:ApplicationInsights").Bind(options);
                });
                services.AddApplicationInsightsTelemetryProcessor<TelemetryProcessor>();
            }

            ConfigureAuthentication(services);
            ConfigureAuthorization(services);
            ConfigureProxy(services);

            services.AddHealthChecks();
        }

        private void ConfigureAuthentication(IServiceCollection services)
        {
            services.AddScoped<IAuthenticationHandlerProvider, FilteredAuthenticationHandlerProvider>();

            var authBuilder = services.AddAuthentication();
            foreach (var application in _options.Applications)
            {
                var schemes = ProxyAuthComponents.GetAuthSchemes(application);
                var idp = _options.IdentityProviders.Single(i => i.Name == application.IdentityProviderBinding.Name);

                if (application.HasPathMode(PathAuthOptions.AuthMode.Api))
                {
                    authBuilder.AddAzureADBearer(
                        scheme: schemes.ApiName,
                        jwtBearerScheme: schemes.JwtBearerName,
                        configureOptions: options =>
                        {
                            options.Instance = idp.Instance;
                            options.TenantId = idp.TenantId;
                            options.ClientId = application.IdentityProviderBinding.ClientId;
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
                            options.Instance = idp.Instance;
                            options.TenantId = idp.TenantId;
                            options.ClientId = application.IdentityProviderBinding.ClientId;
                            options.ClientSecret = application.IdentityProviderBinding.ClientSecret;
                            options.CallbackPath = ProxyMetaEndpoints.FullPath(ProxyMetaEndpoints.SignInCallback);
                            options.SignedOutCallbackPath = ProxyMetaEndpoints.FullPath(ProxyMetaEndpoints.SignedOutCallback);
                        });
                }

                services.Configure<JwtBearerOptions>(schemes.JwtBearerName, options =>
                {
                    options.TokenValidationParameters.ValidAudiences = new string[] { application.IdentityProviderBinding.AppIdUri };
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

                services.Configure<CookieAuthenticationOptions>(schemes.CookieName, options =>
                {
                    options.AccessDeniedPath = ProxyMetaEndpoints.FullPath(ProxyMetaEndpoints.AccessDenied);
                    options.Cookie.SameSite = application.SessionCookieSameSiteMode ?? SameSiteMode.Lax;
                    options.Cookie.Name = $"{ProxyAuthComponents.CookiePrefix}.{ProxyAuthComponents.AuthCookieId}.{application.Name}";
                });

                services.Configure<OpenIdConnectOptions>(schemes.OpenIdName, options =>
                {
                    options.ClaimActions.DeleteClaims("aio", "family_name", "given_name", "name", "sub", "tid", "unique_name", "uti");

                    options.TokenValidationParameters.AuthenticationType = ProxyAuthComponents.WebAuth;
                    options.TokenValidationParameters.RoleClaimType = AzureADClaims.Roles;
                    options.TokenValidationParameters.NameClaimType = AzureADClaims.UserPrincipalName;
                    options.RemoteSignOutPath = ProxyMetaEndpoints.FullPath(ProxyMetaEndpoints.RemoteSignOut);
                    options.ResponseType = application.IdentityProviderBinding.DisableImplicitIdToken ? 
                        OpenIdConnectResponseType.Code : OpenIdConnectResponseType.IdToken;

                    options.SecurityTokenValidator = new JwtSecurityTokenHandler
                    {
                        MapInboundClaims = false
                    };
                });
            }
        }

        private void ConfigureAuthorization(IServiceCollection services)
        {
            services.AddTransient<IPolicyEvaluator, StatusPolicyEvaluator>();
            services.AddAuthorization(options => CreateAuthorizationPolicies(options, _options));
        }

        private static void CreateAuthorizationPolicies(AuthorizationOptions authOptions, ApplicationOptions options)
        {
            foreach (var application in options.Applications)
            {
                var schemes = ProxyAuthComponents.GetAuthSchemes(application);

                if (application.HasPathMode(PathAuthOptions.AuthMode.Api))
                {
                    authOptions.AddPolicy(ProxyAuthComponents.GetApiPolicyName(application), builder =>
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
                    authOptions.AddPolicy(ProxyAuthComponents.GetWebPolicyName(application), builder =>
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
            services.AddSingleton<KerberosIdentityService>();
            services.AddSingleton<IAuthenticatorProvider, AuthenticatorProvider>();
            services.AddMemoryCache();

            foreach (var application in _options.Applications)
            {
                services.AddHttpClient(application.Name).ConfigureHttpMessageHandlerBuilder(builder =>
                {
                    var primaryHandler = new HttpClientHandler
                    {
                        AllowAutoRedirect = false,
                        UseCookies = false,
                        UseProxy = false
                    };

                    var authenticatorProvider = builder.Services.GetService<IAuthenticatorProvider>();
                    foreach (var authenticator in authenticatorProvider[application.Name])
                        authenticator.Configure(builder);
                })
                .ConfigureHttpClient(client => {
                    client.BaseAddress = application.Destination;
                });
            }

            services.Configure<HostFilteringOptions>(options =>
            {
                options.AllowedHosts = _options.Applications.Select(x => x.Host.Value.Value).ToArray();
            });
        }

        public void Configure(IApplicationBuilder app, IApplicationLifetime host)
        {
            if (_options is null)
            {
                host.StopApplication();
                return;
            }

            // Warm up the authentication provider service before first request
            Task.Run(() => app.ApplicationServices.GetService<IAuthenticatorProvider>());

            if (_options.Server.EnableHealthChecks)
                app.UseHealthChecks(ProxyMetaEndpoints.FullPath(ProxyMetaEndpoints.Health));
            app.UseStatusCodePages(Errors.StatusPageAsync);
            app.UseExceptionHandler(new ExceptionHandlerOptions { ExceptionHandler = Errors.Handle });
            if (_options.Server.UseForwardedHeaders)
                app.UseForwardedHeaders();            
            app.UseHostFiltering();
            app.UseAuthentication();
            app.Map(ProxyMetaEndpoints.PathBase, ConfigureMetaPath);
            app.UsePolicyEvaluation();
            app.RunProxy();
        }

        private void ConfigureMetaPath(IApplicationBuilder app)
        {
            app.UseWhen(
                context => context.Request.Path.StartsWithSegments(ProxyMetaEndpoints.AuthenticatedPathBase), 
                a => a.UsePolicyEvaluation());
            app.RunProxyMeta();
        }
    }
}
