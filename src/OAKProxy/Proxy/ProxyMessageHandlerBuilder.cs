using Microsoft.Extensions.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace OAKProxy.Proxy
{
    public class ProxyMessageHandlerBuilder
    {
        private readonly HttpMessageHandlerBuilder _builder;
        private Lazy<HttpClientHandler> _anonymousHandler = new Lazy<HttpClientHandler>(() => CreateDefaultPrimaryClient());

        internal ProxyMessageHandlerBuilder(HttpMessageHandlerBuilder builder)
        {
            _builder = builder;
            _builder.PrimaryHandler = CreateDefaultPrimaryClient();

            AuthenticatorHandlers = new List<AuthenticatorHandler>();
        }

        public HttpClientHandler PrimaryAuthenticatedHandler
        {
            get => (HttpClientHandler)_builder.PrimaryHandler;
        }

        public HttpClientHandler PrimaryAnonymousHandler
        {
            get => _anonymousHandler.Value;
        }

        public IList<AuthenticatorHandler> AuthenticatorHandlers { get; private set; }

        public IServiceProvider Services
        {
            get => _builder.Services;
        }

        internal static HttpClientHandler CreateDefaultPrimaryClient() =>
            new HttpClientHandler
            {
                AllowAutoRedirect = false,
                UseCookies = false,
                UseProxy = false
            };

        internal void PostConfigure()
        {
            var finalAuthenticator = AuthenticatorHandlers.LastOrDefault();
            if (finalAuthenticator != null)
            {
                finalAuthenticator.AnonymousHandler = new ExposingHandler(_anonymousHandler.IsValueCreated ? 
                    _anonymousHandler.Value : CreateDefaultPrimaryClient());

                foreach (var authenticator in AuthenticatorHandlers)
                {
                    _builder.AdditionalHandlers.Add(authenticator);
                }
            }
        }
    }
}