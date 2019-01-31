using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAKProxy.Proxy
{
    public class OAKProxyOptions
    {
        public OKProxiedApplication[] ProxiedApplications { get; set; }

        public OKProxySidMatchingOption SidMatching { get; set; }
    }

    public class OKProxiedApplication
    {
        public string Audience { get; set; }

        public Uri Destination { get; set; }
    }

    public enum OKProxySidMatchingOption
    {
        Never,
        First,
        Only
    }
}
