using Microsoft.Extensions.Http;

namespace OAKProxy.Proxy
{
    public interface IAuthenticator
    {
        void Configure(ProxyMessageHandlerBuilder builder);
    }
}