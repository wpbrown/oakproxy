using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using OAKProxy.PolicyEvaluator;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text.RegularExpressions;

namespace OAKProxy.Proxy
{
    public class ProxyServiceBuilder
    {
        private readonly ProxyOptions _proxyOptions;

        public ProxyServiceBuilder(ProxyOptions proxyOptions)
        {
            _proxyOptions = proxyOptions;
        }

        public void ConfigureAuthentication(IServiceCollection services)
        {
            services.AddScoped<IAuthenticationHandlerProvider, FilteredAuthenticationHandlerProvider>();

            var authBuilder = services.AddAuthentication();
            foreach (var application in _proxyOptions.Applications)
            {
                var idp = _proxyOptions.IdentityProviders.Single(i => i.Name == application.IdentityProviderBinding.Name);
                var additionalClaimsRetained = GetAllNeededClaims(application, _proxyOptions);
                //if (additionalClaimsRetained != null)
                //{
                //    _logger.LogInformation("These claims will be automatically retained for application '{Application}': {Claims}.", application.Name, String.Join(", ", additionalClaimsRetained));
                //}

                bool retainWebToken = false;
                bool retainApiToken = false;
                var bearerAuthenticators = application.AuthenticatorBindings?
                    .Select(b => _proxyOptions.Authenticators.Single(a => a.Name == b.Name))
                    .Where(a => a.Type == AuthenticatorType.Bearer);
                if (bearerAuthenticators?.Count() > 0)
                {
                    retainWebToken = bearerAuthenticators.Any(a => a.PassWebIdToken == true);
                    retainApiToken = bearerAuthenticators.Any(a => a.PassApiAccessToken == true);
                }

                if (idp.Type == IdentityProviderType.AzureAD)
                {
                    ConfigureAzureADAuth(authBuilder, application, idp);
                    ConfigureAzureADAuthOptions(services, application, additionalClaimsRetained, retainWebToken, retainApiToken);
                }
                else // idp.Type == IdentityProviderType.OpenIDConnect
                {
                    // TODO claims management
                    ConfigureOpenIDConnectAuth(authBuilder, application, idp, retainWebToken, retainApiToken);
                }
            }
        }

        private static readonly Regex claimRegex = new Regex(@"(?:^|\b)c\[""(.+?)""\]", RegexOptions.Compiled);
        private string[] GetAllNeededClaims(ProxyApplication application, ProxyOptions options)
        {
            var headerAuthenticators  = application.AuthenticatorBindings?
                .Select(b => options.Authenticators.Single(a => a.Name == b.Name))
                .Where(a => a.Type == AuthenticatorType.Headers);

            if (headerAuthenticators?.Count() > 0)
            {
                var claims = new List<string>();
                foreach (var definition in headerAuthenticators.SelectMany(headerOptions => headerOptions.HeaderDefinitions))
                {
                    if (definition.ClaimName != null)
                    {
                        claims.Add(definition.ClaimName);
                    }
                    else
                    {
                        var matches = claimRegex.Matches(definition.Expression);
                        claims.AddRange(matches.Select(m => m.Groups[1].Value));
                    }
                }
                if (claims.Count > 0)
                {
                    return claims.ToArray();
                }
            }

            return null;
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

        private static void ConfigureAzureADAuthOptions(IServiceCollection services, ProxyApplication application, string[] additionalClaimsRetained, bool retainWebToken, bool retainApiToken)
        {
            var schemes = ProxyAuthComponents.GetAuthSchemes(application);

            if (application.HasPathMode(PathAuthOptions.AuthMode.Api))
            {
                services.Configure<JwtBearerOptions>(schemes.JwtBearerName, options =>
                {
                    options.SaveToken = retainApiToken;
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
                    var stripClaims = new List<string> { "aio", "family_name", "given_name", "name", "tid", "unique_name", "uti" };
                    if (additionalClaimsRetained != null)
                    {
                        foreach (var claim in additionalClaimsRetained)
                        {
                            options.ClaimActions.Remove(claim);
                        }
                        stripClaims = stripClaims.Except(additionalClaimsRetained).ToList();
                    }
                    if (application.SessionCookieRetainedClaims != null)
                    {
                        foreach (var claim in application.SessionCookieRetainedClaims)
                        {
                            options.ClaimActions.Remove(claim);
                        }
                        stripClaims = stripClaims.Except(application.SessionCookieRetainedClaims).ToList();
                    }
                    if (application.SessionCookieStrippedClaims != null)
                    {
                        stripClaims.AddRange(application.SessionCookieStrippedClaims);
                    }
                    options.ClaimActions.DeleteClaims(stripClaims.ToArray());

                    options.SaveTokens = retainWebToken;
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

        private static void ConfigureOpenIDConnectAuth(AuthenticationBuilder authBuilder, ProxyApplication application, IdentityProvider idp, bool retainWebToken, bool retainApiToken)
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
                    options.SaveToken = retainApiToken;
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
                    options.SaveTokens = retainWebToken;
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

        public void ConfigureAuthorization(IServiceCollection services)
        {
            services.AddTransient<IPolicyEvaluator, StatusPolicyEvaluator>();
            services.AddAuthorization(options => CreateAuthorizationPolicies(options, _proxyOptions));
        }

        private static void CreateAuthorizationPolicies(AuthorizationOptions authOptions, ProxyOptions options)
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

        public void ConfigureProxy(IServiceCollection services)
        {
            services.AddScoped<IProxyApplicationService, ProxyApplicationService>();
            services.AddSingleton<KerberosIdentityService>();
            services.AddSingleton<IAuthenticatorProvider, AuthenticatorProvider>();
            services.AddSingleton<IClaimsProviderProvider, ClaimsProviderProvider>();
            services.AddMemoryCache();

            foreach (var application in _proxyOptions.Applications)
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

            services.AddHostFiltering(options =>
            {
                options.AllowedHosts = _proxyOptions.Applications.Select(x => x.Host.Value.Value).ToArray();
            });
        }
    }
}
