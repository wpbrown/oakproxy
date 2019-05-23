using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAKProxy.Proxy
{
    public class ProxyApplicationService : IProxyApplicationService
    {
        private readonly ProxyApplication _activeApplication;
        private readonly OAKProxyOptions _options;

        public ProxyApplicationService(IHttpContextAccessor context, IOptions<OAKProxyOptions> options)
        {
            _options = options.Value;

            // Should never fail. Host filtering middleware should short-circuit requests for unknown
            // hosts.
            HostString requestHost = context.HttpContext.Request.Host;
            _activeApplication = _options.ProxiedApplications.First(app => app.Host == requestHost);
        }

        public ProxyApplication GetActiveApplication()
        {
            return _activeApplication;
        }
    }
}
