using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAKProxy.Proxy
{
    public class OAKProxyOptions
    {
        public OKProxiedApplication[] ProxiedApplications { get; set; }

        public OKProxyServicePrincipalMapping[] ServicePrincipalMappings { get; set; }

        public OKProxySidMatchingOption SidMatching { get; set; }

        public bool BehindReverseProxy { get; set; }
    }

    public class OKProxiedApplication
    {
        public string Name { get; set; }

        public string Host { get; set; }

        public string ClientId { get; set; }

        public string AppdIdUri { get; set; }

        public Uri Destination { get; set; }
    }

    public class OKProxyServicePrincipalMapping
    {
        public string ObjectId { get; set; }

        public string UserPrincipalName { get; set; }
    }

    public enum OKProxySidMatchingOption
    {
        Never,
        First,
        Only
    }
}
