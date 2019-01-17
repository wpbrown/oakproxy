using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAKProxy.Proxy
{
    public class OKProxyOptions
    {
        public OKProxiedApplication[] ProxiedApplications { get; set; }
    }

    public class OKProxiedApplication
    {
        public string Audience { get; set; }

        public Uri Destination { get; set; }
    }
}
