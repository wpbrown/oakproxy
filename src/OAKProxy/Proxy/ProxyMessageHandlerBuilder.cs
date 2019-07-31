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
        private Lazy<SocketsHttpHandler> _anonymousHandler = new Lazy<SocketsHttpHandler>(() => CreateDefaultPrimaryClient());

        internal ProxyMessageHandlerBuilder(HttpMessageHandlerBuilder builder)
        {
            _builder = builder;
            _builder.PrimaryHandler = CreateDefaultPrimaryClient();

            AuthenticatorHandlers = new List<AuthenticatorHandler>();
        }

        public SocketsHttpHandler PrimaryAuthenticatedHandler
        {
            get => (SocketsHttpHandler)_builder.PrimaryHandler;
        }

        public SocketsHttpHandler PrimaryAnonymousHandler
        {
            get => _anonymousHandler.Value;
        }

        public IList<AuthenticatorHandler> AuthenticatorHandlers { get; private set; }

        public IServiceProvider Services
        {
            get => _builder.Services;
        }

        internal static SocketsHttpHandler CreateDefaultPrimaryClient() =>
            new SocketsHttpHandler
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