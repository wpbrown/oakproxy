using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.ComponentModel.DataAnnotations;
using System.Linq;

namespace OAKProxy.Proxy
{
    public class ApplicationOptions : IValidateOptions<ApplicationOptions>
    {
        [Required, ValidateObject]
        public ServerOptions Server { get; set; }

        [Required, MinLength(1), ValidateCollection]
        public ProxyApplication[] Applications { get; set; }

        [Required, MinLength(1), ValidateCollection]
        public IdentityProvider[] IdentityProviders { get; set; }

        [Required, MinLength(1), ValidateCollection]
        public Authenticator[] Authenticators { get; set; }

        public ValidateOptionsResult Validate(string _, ApplicationOptions options)
        {
            if (options.Applications is null)
                return ValidateOptionsResult.Success;

            foreach (var application in options.Applications)
            {
                var name = application.IdentityProviderBinding.Name;
                if (options.IdentityProviders is null || !options.IdentityProviders.Any(i => i.Name == name))
                    return ValidateOptionsResult.Fail($"No identity provider with name '{name}' configured.");

                foreach (var authBinding in application.AuthenticatorBindings)
                {
                    var authName = authBinding.Name;
                    if (options.Authenticators is null || !options.Authenticators.Any(a => a.Name == authName))
                        return ValidateOptionsResult.Fail($"No authenticator with name '{authName}' configured.");
                }
            }

            return ValidateOptionsResult.Success;
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

    public class Authenticator
    {
        [Required]
        public AuthenticatorType? Type { get; set; }

        [Required]
        public string Name { get; set; }

        public SidMatchingOption SidMatching { get; set; }

        [ValidateCollection]
        public ServicePrincipalMapping[] ServicePrincipalMappings { get; set; }
    }

    public class IdentityProviderBinding
    {
        [Required]
        public string Name { get; set; }

        [Required]
        public string ClientId { get; set; }

        [Required]
        public string AppIdUri { get; set; }
    }

    public class AuthenticatorBinding
    {
        [Required]
        public string Name { get; set; }
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

    public class ProxyApplication
    {
        [Required]
        public string Name { get; set; }

        [Required, ValidateObject]
        public IdentityProviderBinding IdentityProviderBinding { get; set; }

        [Required, ValidateCollection]
        public AuthenticatorBinding[] AuthenticatorBindings { get; set; }

        [Required]
        public HostString? Host { get; set; }

        [Required]
        public Uri Destination { get; set; }

        [ValidateCollection]
        public PathAuthOptions[] PathAuthOptions { get; set; }

        public bool ApiAllowWebSession { get; set; }

        public bool WebRequireRoleClaim { get; set; }

        public PathAuthOptions.AuthMode? GetPathMode(PathString path)
        {
            var options = PathAuthOptions.FirstOrDefault(o => path.StartsWithSegments(o.Path));
            return options?.Mode.Value;
        }

        public bool HasPathMode(PathAuthOptions.AuthMode mode)
        {
            return PathAuthOptions.Any(o => o.Mode.Value == mode);
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
        [Required]
        public PathString Path { get; set; }

        [Required]
        public AuthMode? Mode { get; set; }

        public enum AuthMode
        {
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
        Kerberos
    }
}
