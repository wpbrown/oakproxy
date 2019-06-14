using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HostFiltering;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Services.AppAuthentication;
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
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
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

            // Header Forwarding
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

            // Application Insights
            if (!String.IsNullOrWhiteSpace(_options.Server.ApplicationInsightsKey))
            {
                services.AddApplicationInsightsTelemetry(options =>
                {
                    options.InstrumentationKey = _options.Server.ApplicationInsightsKey;
                    _configuration.GetSection("Configuration:ApplicationInsights").Bind(options);
                });
                services.AddApplicationInsightsTelemetryProcessor<TelemetryProcessor>();
            }

            // Key Management
            if (_options.Server.KeyManagement != null)
            {
                var dataProtectionBuilder = services.AddDataProtection();
                var kmOptions = _options.Server.KeyManagement;

                kmOptions.LoadCertificates(_configuration.GetSection("Server:KeyManagement"));

                if (!String.IsNullOrEmpty(kmOptions.StoreToFilePath))
                {
                    var directoryInfo = new DirectoryInfo(kmOptions.StoreToFilePath);
                    if (!directoryInfo.Exists)
                    {
                        throw new DirectoryNotFoundException("The specified key storage directory does not exist.");
                    }
                    dataProtectionBuilder.PersistKeysToFileSystem(directoryInfo);
                }
                else if (!String.IsNullOrEmpty(kmOptions.StoreToBlobContainer))
                {
                    // Upgrade to support Managed Identity after .NET Core 3.0. This API is updated to use
                    // new storage SDK in 3.0.
                    dataProtectionBuilder.PersistKeysToAzureBlobStorage(new Uri(kmOptions.StoreToBlobContainer));
                }

                if (!String.IsNullOrEmpty(kmOptions.ProtectWithKeyVaultKey))
                {
                    var keyVaultSection = _configuration?.GetSection("Server:KeyVault");
                    var kvOptions = new KeyVaultOptions(keyVaultSection);

                    var keyIdBuilder = new UriBuilder(kvOptions.VaultUri)
                    {
                        Path = $"/keys/${kmOptions.ProtectWithKeyVaultKey}"
                    };
                    var keyId = keyIdBuilder.Uri.ToString();

                    // TODO: Unify configuration and key management key vault clients
                    if (kvOptions.ClientId == null)
                    {
                        // Use Managed Identity
                        var azureServiceTokenProvider = new AzureServiceTokenProvider();
                        var authenticationCallback = new KeyVaultClient.AuthenticationCallback(azureServiceTokenProvider.KeyVaultTokenCallback);
                        dataProtectionBuilder.ProtectKeysWithAzureKeyVault(new KeyVaultClient(authenticationCallback), keyId);
                    }
                    else
                    {
                        if (kvOptions.ClientSecret != null)
                        {
                            dataProtectionBuilder.ProtectKeysWithAzureKeyVault(keyId, kvOptions.ClientId, kvOptions.ClientSecret);
                        }
                        else if (kvOptions.Certificate != null)
                        {
                            dataProtectionBuilder.ProtectKeysWithAzureKeyVault(keyId, kvOptions.ClientId, kvOptions.Certificate);
                        }
                    }
                }
                else if (kmOptions.ProtectWithCertificate != null)
                {
                    dataProtectionBuilder.ProtectKeysWithCertificate(kmOptions.ProtectWithCertificate);

                    if (kmOptions.UnprotectWithCertificates != null)
                    {
                        dataProtectionBuilder.UnprotectKeysWithAnyCertificate(kmOptions.UnprotectWithCertificates);
                    }
                }
                else if (kmOptions.ProtectWithDpapiNg != null)
                {
                    if (kmOptions.ProtectWithDpapiNg.UseSelfRule)
                    {
                        dataProtectionBuilder.ProtectKeysWithDpapiNG();
                    }
                    else
                    {
                        dataProtectionBuilder.ProtectKeysWithDpapiNG(kmOptions.ProtectWithDpapiNg.DescriptorRule, kmOptions.ProtectWithDpapiNg.DescriptorFlags);
                    }
                }
                else
                {
                    throw new Exception("Unvalidated options would have allowed for unprotected key storage.");
                }
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
                var idp = _options.IdentityProviders.Single(i => i.Name == application.IdentityProviderBinding.Name);
                if (idp.Type == IdentityProviderType.AzureAD)
                {
                    ConfigureAzureADAuth(authBuilder, application, idp);
                }
            }

            // Additional configuration is done after all AzureAD configuration due to a bug fixed in ASP.NET Core 3.0:
            // https://github.com/aspnet/AspNetCore/commit/23c528c176e654e14cf5d078558420e00154d0e6
            // Remerge this logic to the loop function above after migration to 3.0.
            foreach (var application in _options.Applications)
            {
                var idp = _options.IdentityProviders.Single(i => i.Name == application.IdentityProviderBinding.Name);
                if (idp.Type == IdentityProviderType.AzureAD)
                {
                    ConfigureAzureADAuthOptions(services, application);
                }
                else // idp.Type == IdentityProviderType.OpenIDConnect
                {
                    ConfigureOpenIDConnectAuth(authBuilder, application, idp);
                }
            }
        }

        private static void ConfigureAzureADAuth(AuthenticationBuilder authBuilder, ProxyApplication application, IdentityProvider idp)
        {
            var schemes = ProxyAuthComponents.GetAuthSchemes(application);
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
        }

        private static void ConfigureAzureADAuthOptions(IServiceCollection services, ProxyApplication application)
        {
            var schemes = ProxyAuthComponents.GetAuthSchemes(application);

            if (application.HasPathMode(PathAuthOptions.AuthMode.Api))
            {
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
            }

            if (application.HasPathMode(PathAuthOptions.AuthMode.Web))
            {
                services.Configure<CookieAuthenticationOptions>(schemes.CookieName, options =>
                {
                    options.AccessDeniedPath = ProxyMetaEndpoints.FullPath(ProxyMetaEndpoints.AccessDenied);
                    options.Cookie.SameSite = application.SessionCookieSameSiteMode ?? SameSiteMode.Lax;
                    options.Cookie.Name = $"{ProxyAuthComponents.CookiePrefix}.{ProxyAuthComponents.AuthCookieId}.{application.Name}";
                });

                services.Configure<OpenIdConnectOptions>(schemes.OpenIdName, options =>
                {
                    options.ClaimActions.DeleteClaims("aio", "family_name", "given_name", "name", "tid", "unique_name", "uti");

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

                    if (application.IdentityProviderBinding.UseApplicationMetadata)
                    {
                        options.MetadataAddress = $"{options.Authority}/.well-known/openid-configuration?appid={options.ClientId}";
                    }
                });
            }
        }

        private static void ConfigureOpenIDConnectAuth(AuthenticationBuilder authBuilder, ProxyApplication application, IdentityProvider idp)
        {
            var schemes = ProxyAuthComponents.GetAuthSchemes(application);

            if (application.HasPathMode(PathAuthOptions.AuthMode.Api))
            {
                authBuilder.AddJwtBearer(schemes.ApiName, options =>
                {
                    options.Authority = idp.Authority;
                    if (idp.AccessTokenIssuer != null)
                    {
                        options.TokenValidationParameters.ValidIssuer = idp.AccessTokenIssuer;
                    }
                    
                    options.Audience = application.IdentityProviderBinding.ClientId;
                    options.TokenValidationParameters.ValidAudiences = new string[] { application.IdentityProviderBinding.AppIdUri };
                    options.TokenValidationParameters.AuthenticationType = ProxyAuthComponents.ApiAuth;
                    options.SecurityTokenValidators.Clear();
                    options.SecurityTokenValidators.Add(new JwtSecurityTokenHandler
                    {
                        MapInboundClaims = false
                    });
                });
            }

            if (application.HasPathMode(PathAuthOptions.AuthMode.Web))
            {
                authBuilder.AddOpenIdConnect(schemes.OpenIdName, options =>
                {
                    options.ClientId = application.IdentityProviderBinding.ClientId;
                    options.ClientSecret = application.IdentityProviderBinding.ClientSecret;
                    options.Authority = idp.Authority;
                    options.CallbackPath = ProxyMetaEndpoints.FullPath(ProxyMetaEndpoints.SignInCallback);
                    options.SignedOutCallbackPath = ProxyMetaEndpoints.FullPath(ProxyMetaEndpoints.SignedOutCallback);
                    options.SignInScheme = schemes.WebName;
                    options.UseTokenLifetime = true;
                    options.TokenValidationParameters.AuthenticationType = ProxyAuthComponents.WebAuth;
                    options.RemoteSignOutPath = ProxyMetaEndpoints.FullPath(ProxyMetaEndpoints.RemoteSignOut);
                    options.SecurityTokenValidator = new JwtSecurityTokenHandler
                    {
                        MapInboundClaims = false
                    };
                });
                authBuilder.AddCookie(schemes.WebName, options =>
                {
                    options.AccessDeniedPath = ProxyMetaEndpoints.FullPath(ProxyMetaEndpoints.AccessDenied);
                    options.Cookie.SameSite = application.SessionCookieSameSiteMode ?? SameSiteMode.Lax;
                    options.Cookie.Name = $"{ProxyAuthComponents.CookiePrefix}.{ProxyAuthComponents.AuthCookieId}.{application.Name}";
                    options.ForwardChallenge = schemes.OpenIdName;
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
                        {
                            bool isAzureAD = options.IdentityProviders.First(i => i.Name == application.IdentityProviderBinding.Name).Type == IdentityProviderType.AzureAD;
                            if (isAzureAD)
                            {
                                apiSchemes.Add(schemes.CookieName);
                            } 
                            else
                            {
                                apiSchemes.Add(schemes.WebName);
                            }
                        }

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
            services.AddSingleton<IClaimsProviderProvider, ClaimsProviderProvider>();
            services.AddMemoryCache();

            foreach (var application in _options.Applications)
            {
                services.AddHttpClient(application.Name).ConfigureHttpMessageHandlerBuilder(builder =>
                {
                    var proxyBuilder = new ProxyMessageHandlerBuilder(builder);
                   
                    var authenticatorProvider = builder.Services.GetService<IAuthenticatorProvider>();
                    foreach (var authenticator in authenticatorProvider[application.Name])
                        authenticator.Configure(proxyBuilder);

                    proxyBuilder.PostConfigure();
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

            var authenticatorWarmup = Task.Run(() => app.ApplicationServices.GetService<IAuthenticatorProvider>());

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

            authenticatorWarmup.Wait();
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
