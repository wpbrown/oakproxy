using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAKProxy.Proxy
{
    public class OAKProxyOptions
    {
        public ProxyApplication[] ProxiedApplications { get; set; }

        public ServicePrincipalMapping[] ServicePrincipalMappings { get; set; }

        public SidMatchingOption SidMatching { get; set; }

        public bool BehindReverseProxy { get; set; }
    }

    public class ProxyApplication
    {
        public string Name { get; set; }

        public string ClientId { get; set; }

        public string AppIdUri { get; set; }

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
}
