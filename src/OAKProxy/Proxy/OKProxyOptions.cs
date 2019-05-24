using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAKProxy.Proxy
{
    public class ApplicationOptions
    {
        public ServerOptions Server { get; set; }

        public ProxyApplication[] Applications { get; set; }

        public IdentityProvider[] IdentityProviders { get; set; }

        public Authenticator[] Authenticators { get; set; }
    }

    public class IdentityProvider
    {
        public IdentityProviderType Type { get; set; }

        public string Name { get; set; }

        public string Instance { get; set; } 

        public string TenantId { get; set; }
    }

    public class Authenticator
    {
        public AuthenticatorType Type { get; set; }

        public string Name { get; set; }

        public SidMatchingOption SidMatching { get; set; }

        public ServicePrincipalMapping[] ServicePrincipalMappings { get; set; }
    }

    public class IdentityProviderBinding
    {
        public string Name { get; set; }

        public string ClientId { get; set; }

        public string AppIdUri { get; set; }
    }

    public class AuthenticatorBinding
    {
        public string Name { get; set; }
    }

    public class ServerOptions
    {
        public bool UseForwardedHeaders { get; set; }

        public LogLevel LogLevel { get; set; }

        public string ApplicationInsightsKey { get; set; }

        public string Urls { get; set; }
    }

    public class ProxyApplication
    {
        public string Name { get; set; }

        public IdentityProviderBinding IdentityProviderBinding { get; set; }

        public AuthenticatorBinding[] AuthenticatorBindings { get; set; }

        public HostString Host { get; set; }

        public Uri Destination { get; set; }

        public PathAuthOptions[] PathAuthOptions { get; set; }

        public bool ApiAllowWebSession { get; set; }

        public bool WebRequireRoleClaim { get; set; }

        public PathAuthOptions.AuthMode? GetPathMode(PathString path)
        {
            var options = PathAuthOptions.FirstOrDefault(o => path.StartsWithSegments(o.Path));
            return options?.Mode;
        }

        public bool HasPathMode(PathAuthOptions.AuthMode mode)
        {
            return PathAuthOptions.Any(o => o.Mode == mode);
        }
    }

    public class ServicePrincipalMapping
    {
        public string ObjectId { get; set; }

        public string UserPrincipalName { get; set; }
    }

    public class PathAuthOptions
    {
        public PathString Path { get; set; }

        public AuthMode Mode { get; set; }

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
