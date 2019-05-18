using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using OAKProxy.Proxy;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAKProxy.PolicyEvaluator
{
    public class FilteredAuthenticationHandlerProvider : IAuthenticationHandlerProvider
    {
        private AuthenticationHandlerProvider _provider;
        private ProxyService _proxyService;

        public FilteredAuthenticationHandlerProvider(IAuthenticationSchemeProvider schemes, ProxyService proxyService)
        {
            _provider = new AuthenticationHandlerProvider(schemes);
            _proxyService = proxyService;
        }

        public Task<IAuthenticationHandler> GetHandlerAsync(HttpContext context, string authenticationScheme)
        {
            string application = _proxyService.GetActiveApplication(context.Request.Host.Host);
            if (!authenticationScheme.StartsWith(application + "."))
                return Task.FromResult<IAuthenticationHandler>(null);

            return _provider.GetHandlerAsync(context, authenticationScheme);
        }
    }
}
