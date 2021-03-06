﻿using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OAKProxy.Authenticator.Bearer;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace OAKProxy.Proxy
{
    public class ProxyOptions : IValidatableObject
    {
        [Required, MinLength(1), ValidateCollection]
        public ProxyApplication[] Applications { get; set; }

        [Required, MinLength(1), ValidateCollection]
        public IdentityProvider[] IdentityProviders { get; set; }

        [ValidateCollection]
        public AuthenticatorOptionsBase[] Authenticators { get; set; }

        [ValidateCollection]
        public ClaimsProviderOptionsBase[] ClaimsProviders { get; set; }

        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
            foreach (var application in Applications)
            {
                var name = application.IdentityProviderBinding.Name;
                if (!IdentityProviders.Any(i => i.Name == name))
                    yield return new ValidationResult($"No identity provider with name '{name}' configured.", new string[] { nameof(Applications) });

                if (application.AuthenticatorBindings != null)
                {
                    foreach (var authBinding in application.AuthenticatorBindings)
                    {
                        var authName = authBinding.Name;
                        if (Authenticators is null || !Authenticators.Any(a => a.Name == authName))
                            yield return new ValidationResult($"No authenticator with name '{authName}' configured.", new string[] { nameof(Applications) });
                    }
                }
            }
        }
    }

    public class IdentityProvider
    {
        [Required]
        public IdentityProviderType? Type { get; set; }

        [Required]
        public string Name { get; set; }

        // AzureAD
        //[Required]
        public string Instance { get; set; }

        //[Required]
        public string TenantId { get; set; }

        // OpenIDConenct
        public string Authority { get; set; }

        public string AccessTokenIssuer { get; set; }
    }

    public class AuthenticatorOptionsBase : IValidatableObject
    {
        [Required]
        public AuthenticatorType? Type { get; set; }

        [Required]
        public string Name { get; set; }

        // Kerberos
        [Required]
        public string DomainUpnClaimName { get; set; } = "onprem_upn";

        // Headers
        [ValidateCollection]
        public HeaderDefinition[] HeaderDefinitions { get; set; }

        // Bearer
        public bool PassWebIdToken { get; set; }

        public bool PassApiAccessToken { get; set; }

        public string HeaderName { get; set; }

        public Type ImplType
        {
            get
            {
                switch (Type.Value)
                {
                    case AuthenticatorType.Kerberos:
                        return typeof(KerberosAuthenticator);
                    case AuthenticatorType.Headers:
                        return typeof(HeadersAuthenticator);
                    case AuthenticatorType.Bearer:
                        return typeof(BearerAuthenticator);
                    default:
                        throw new Exception("Unknown authenticator type.");
                }
            }
        }

        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
#if !ENABLE_KERBEROS_AUTHENTICATOR
            if (Type == AuthenticatorType.Kerberos)
                yield return new ValidationResult($"{nameof(Type)} {nameof(AuthenticatorType.Kerberos)} is not supported in this build. You must install the Kerberos enabled build on Windows Server.", new string[] { nameof(Type) });
#endif
            yield break;
        }
    }

    public class ClaimsProviderOptionsBase : IValidatableObject
    {
        [Required]
        public ClaimsProviderType? Type { get; set; }

        [Required]
        public string Name { get; set; }

        public Type ImplType
        {
            get
            {
                switch (Type.Value)
                {
                    case ClaimsProviderType.DirectoryUpnResolver:
                        return typeof(DirectoryUpnResolver);
                    default:
                        throw new Exception("Unknown claims provider type.");
                }
            }
        }

        // DirectoryUpnResolver
        [Required]
        public string DirectorySidClaimName { get; set; } = "onprem_sid";

        [Required]
        public string IdentityProviderUserClaimName { get; set; } = "upn";

        [Required]
        public string IdentityProviderApplicationClaimName { get; set; } = "oid";

        [Required]
        public string IdentityProviderAnchorClaimName { get; set; } = "sub";

        [Required]
        public string OutputClaimName { get; set; } = "onprem_upn";

        public string DirectoryServerName { get; set; }

        public string DirectoryServerUsername { get; set; }

        public string DirectoryServerPassword { get; set; }

        public DirectoryServerType DirectoryServerType { get; set; }

        public SidMatchingOption SidMatching { get; set; }

        [ValidateCollection]
        public ServicePrincipalMapping[] ServicePrincipalMappings { get; set; }
        

        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
            yield break;
        }
    }

    public class HeaderDefinition : IValidatableObject
    {
        [Required]
        public string HeaderName { get; set; }

        public string ClaimName { get; set; }

        public string Expression { get; set; }

        public bool Required { get; set; }

        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
            if (!String.IsNullOrEmpty(ClaimName) && !String.IsNullOrEmpty(Expression))
            {
                yield return new ValidationResult($"Use {nameof(ClaimName)} or {nameof(Expression)}. Both can not be set.", new string[] { nameof(ClaimName), nameof(Expression) });
            }
        }
    }

    public class IdentityProviderBinding : IValidatableObject
    {
        [Required]
        public string Name { get; set; }

        [Required]
        public string ClientId { get; set; }

        public string AppIdUri { get; set; }

        public string ClientSecret { get; set; }

        public bool DisableImplicitIdToken { get; set; }

        // Azure AD Options
        public bool UseApplicationMetadata { get; set; }

        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
            if (DisableImplicitIdToken && String.IsNullOrWhiteSpace(ClientSecret))
            {
                yield return new ValidationResult($"If {nameof(DisableImplicitIdToken)} is true, then {nameof(ClientSecret)} is required.", new string[] { nameof(DisableImplicitIdToken), nameof(ClientSecret) });
            }
        }
    }

    public class AuthenticatorBindingOptionsBase
    {
        [Required]
        public string Name { get; set; }

        // Kerberos
        public bool SendAnonymousRequestAsService { get; set; }
    }
    
    public class ClaimsProviderBindingOptionsBase
    {
        [Required]
        public string Name { get; set; }
    }

    public class ProxyApplication : IValidatableObject
    {
        [Required]
        public string Name { get; set; }

        internal IdentityProviderBinding IdentityProviderBinding
        {
            get { return IdentityProviderBindings[0]; }
        }

        private const string idpError = "Must contain exactly 1 identity provider binding.";
        [Required, MinLength(1, ErrorMessage = idpError), MaxLength(1, ErrorMessage = idpError), ValidateCollection]
        public IdentityProviderBinding[] IdentityProviderBindings { get; set; }

        [ValidateCollection]
        public AuthenticatorBindingOptionsBase[] AuthenticatorBindings { get; set; }

        [ValidateCollection]
        public ClaimsProviderBindingOptionsBase[] ClaimsProviderBindings { get; set; }

        [Required]
        public HostString? Host { get; set; }

        [Required]
        public Uri Destination { get; set; }

        [Required, MinLength(1), ValidateCollection]
        public PathAuthOptions[] PathAuthOptions { get; set; }

        public bool ApiAllowWebSession { get; set; }

        public bool WebRequireRoleClaim { get; set; }

        public SameSiteMode? SessionCookieSameSiteMode { get; set; }

        public string[] SessionCookieStrippedClaims { get; set; }

        public string[] SessionCookieRetainedClaims { get; set; }

        public PathAuthOptions.AuthMode? GetPathMode(PathString path)
        {
            var options = PathAuthOptions.FirstOrDefault(o => path.StartsWithSegments(o.Path.Value));
            return options?.Mode.Value;
        }

        public bool HasPathMode(PathAuthOptions.AuthMode mode)
        {
            return PathAuthOptions != null && PathAuthOptions.Any(o => o.Mode.Value == mode);
        }

        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
            if (HasPathMode(Proxy.PathAuthOptions.AuthMode.Api) && String.IsNullOrEmpty(IdentityProviderBinding.AppIdUri))
            {
                yield return new ValidationResult($"If any paths use API mode, then {nameof(IdentityProviderBinding.AppIdUri)} is required.", new string[] { nameof(IdentityProviderBinding.AppIdUri) });
            }
        }
    }

    public class ServicePrincipalMapping
    {
        [Required]
        public string ObjectId { get; set; }

        [Required]
        public string UserPrincipalName { get; set; }
    }

    public class PathAuthOptions
    {
        [Required(AllowEmptyStrings = true)]
        public PathString Path { get; set; }

        [Required]
        public AuthMode? Mode { get; set; }

        public enum AuthMode
        {
            None,
            Web,
            Api
        }
    }

    public enum SidMatchingOption
    {
        Never,
        First,
        Only
    }

    public enum IdentityProviderType
    {
        AzureAD,
        OpenIDConnect
    }

    public enum AuthenticatorType
    {
        Kerberos,
        Headers,
        Bearer
    }

    public enum ClaimsProviderType
    {
        DirectoryUpnResolver
    }

    public enum DirectoryServerType
    {
        CurrentDomain,
        LDS
    }
}
