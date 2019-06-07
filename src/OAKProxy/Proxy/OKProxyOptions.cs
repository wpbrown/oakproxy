using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace OAKProxy.Proxy
{
    public class ApplicationOptions : IValidatableObject
    {
        [Required, ValidateObject]
        public ServerOptions Server { get; set; }

        [Required, MinLength(1), ValidateCollection]
        public ProxyApplication[] Applications { get; set; }

        [Required, MinLength(1), ValidateCollection]
        public IdentityProvider[] IdentityProviders { get; set; }

        [ValidateCollection]
        public AuthenticatorOptionsBase[] Authenticators { get; set; }

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

        [Required]
        public string Instance { get; set; }

        [Required]
        public string TenantId { get; set; }
    }

    public class AuthenticatorOptionsBase : IValidatableObject
    {
        [Required]
        public AuthenticatorType? Type { get; set; }

        [Required]
        public string Name { get; set; }

        // Kerberos
        public SidMatchingOption SidMatching { get; set; }

        [ValidateCollection]
        public ServicePrincipalMapping[] ServicePrincipalMappings { get; set; }

        // Headers
        [ValidateCollection]
        public HeaderDefinition[] HeaderDefinitions { get; set; }

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

        // Headers
        public bool SendAnonymousRequestAsService { get; set; }
    }

    public class ServerOptions
    {
        public bool UseForwardedHeaders { get; set; }

        public LogLevel? LogLevel { get; set; }

        public string ApplicationInsightsKey { get; set; }

        [Required]
        public string Urls { get; set; }

        public bool EnableHealthChecks { get; set; }
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

        [Required]
        public HostString? Host { get; set; }

        [Required]
        public Uri Destination { get; set; }

        [Required, MinLength(1), ValidateCollection]
        public PathAuthOptions[] PathAuthOptions { get; set; }

        public bool ApiAllowWebSession { get; set; }

        public bool WebRequireRoleClaim { get; set; }

        public SameSiteMode? SessionCookieSameSiteMode { get; set; }

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
        AzureAD
    }

    public enum AuthenticatorType
    {
        Kerberos,
        Headers
    }

    public class KeyVaultOptions
    {
        public KeyVaultOptions(IConfiguration configuration)
        {
            configuration.Bind(this);

            var certificateSection = configuration.GetSection("Certificate");
            if (certificateSection.Exists())
            {
                if (certificateSection["Path"] != null)
                {
                    var certificateOptions = certificateSection.Get<CertificateFileOptions>();
                    Certificate = new X509Certificate2(certificateOptions.Path, certificateOptions.Password);
                }
                else if (certificateSection["Subject"] != null)
                {
                    var certificateOptions = certificateSection.Get<CertificateStoreOptions>();
                    Certificate = Microsoft.AspNetCore.Server.Kestrel.Https.Internal.CertificateLoader
                        .LoadFromStoreCert(certificateOptions.Subject, 
                            certificateOptions.Store, 
                            certificateOptions.Location, 
                            certificateOptions.AllowInvalid);
                }
            }
        }

        public string Name { get; set; }

        public string ClientId { get; set; }

        public string ClientSecret { get; set; }

        public X509Certificate2 Certificate { get; private set; }
    }

    public class CertificateFileOptions
    {
        public string Path { get; set; }

        public string Password { get; set; }
    }

    public class CertificateStoreOptions
    {
        public string Subject { get; set; }

        public string Store { get; set; }

        public StoreLocation Location { get; set; }

        public bool AllowInvalid { get; set; }
    }
}
