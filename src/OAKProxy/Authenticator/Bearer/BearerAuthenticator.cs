using OAKProxy.Proxy;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Net.Http.Headers;

namespace OAKProxy.Authenticator.Bearer
{
    public class BearerAuthenticator : IAuthenticator
    {
        private readonly AuthenticatorOptionsBase _options;
        private readonly AuthenticatorBindingOptionsBase _bindingOptions;

        public BearerAuthenticator(AuthenticatorOptionsBase options, AuthenticatorBindingOptionsBase bindingOptions)
        {
            _options = options;
            _bindingOptions = bindingOptions;
        }

        public void Configure(ProxyMessageHandlerBuilder builder)
        {
            builder.AuthenticatorHandlers.Add(new BearerHandler()
            {
                Options = _options
            });
        }

        private class BearerHandler : AuthenticatorHandler
        {
            public AuthenticatorOptionsBase Options;

            protected override Task<HttpResponseMessage> SendAsyncAuthenticator(AuthenticatorSendContext context, CancellationToken cancellationToken)
            {
                var tokens = context.AuthenticationProperties.GetTokens();

                string tokenType = null;
                if (Options.PassWebIdToken && tokens.Any(t => t.Name == OpenIdConnectParameterNames.IdToken))
                {
                    tokenType = OpenIdConnectParameterNames.IdToken;
                }
                else if (Options.PassApiAccessToken && tokens.Any(t => t.Name == OpenIdConnectParameterNames.AccessToken))
                {
                    tokenType = OpenIdConnectParameterNames.AccessToken;
                }

                if (tokenType != null)
                {
                    var tokenValue = tokens.First(t => t.Name == tokenType).Value;
                    context.Message.Headers.Add(HeaderNames.Authorization, $"Bearer {tokenValue}");
                }

                return base.SendAsyncAuthenticator(context, cancellationToken);
            }
        }
    }
}
