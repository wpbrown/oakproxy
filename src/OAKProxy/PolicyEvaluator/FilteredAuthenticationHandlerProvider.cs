using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using OAKProxy.Proxy;
using System.Threading.Tasks;

namespace OAKProxy.PolicyEvaluator
{
    public class FilteredAuthenticationHandlerProvider : IAuthenticationHandlerProvider
    {
        private readonly AuthenticationHandlerProvider _provider;
        private readonly IProxyApplicationService _applicationService;

        public FilteredAuthenticationHandlerProvider(IAuthenticationSchemeProvider schemes, IProxyApplicationService applicationService)
        {
            _provider = new AuthenticationHandlerProvider(schemes);
            _applicationService = applicationService;
        }

        public Task<IAuthenticationHandler> GetHandlerAsync(HttpContext context, string authenticationScheme)
        {
            var activeApplication = _applicationService.GetActiveApplication();
            if (!ProxyAuthComponents.IsSchemeForApplication(authenticationScheme, activeApplication))
                return Task.FromResult<IAuthenticationHandler>(null);

            return _provider.GetHandlerAsync(context, authenticationScheme);
        }
    }
}
