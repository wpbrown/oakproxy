using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;
using System;
using System.Net.Http;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;

namespace OAKProxy.Proxy
{
    public class KerberosAuthenticator : IAuthenticator
    {
        private readonly AuthenticatorOptionsBase _options;
        private readonly AuthenticatorBindingOptionsBase _bindingOptions;

        public KerberosAuthenticator(AuthenticatorOptionsBase options, AuthenticatorBindingOptionsBase bindingOptions)
        {
            _options = options;
            _bindingOptions = bindingOptions;
        }

        public void Configure(ProxyMessageHandlerBuilder builder)
        {
            builder.PrimaryAuthenticatedHandler.UseDefaultCredentials = true;

            if (_bindingOptions.SendAnonymousRequestAsService)
            {
                builder.PrimaryAnonymousHandler.UseDefaultCredentials = true;
            }

            builder.AuthenticatorHandlers.Add(new KerberosHandler() {
                Options = _options,
                IdentityService = builder.Services.GetService<KerberosIdentityService>()
            });
        }

        private class KerberosHandler : AuthenticatorHandler
        {
            public AuthenticatorOptionsBase Options;
            public KerberosIdentityService IdentityService;

            protected override Task<HttpResponseMessage> SendAsyncAuthenticator(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                var user = request.GetUser();

                WindowsIdentity domainIdentity = IdentityService.TranslateDomainIdentity(user, Options);
                if (domainIdentity is null)
                {
                    throw new AuthenticatorException(Errors.Code.NoIdentityTranslation, "Identity could not be translated to a domain identity");
                }

                request.Properties.Add("S4uIdentity", domainIdentity);
                request.SetAuthenticatorUser(domainIdentity.Name);
                return base.SendAsyncAuthenticator(request, cancellationToken);
            }
        }
    }
}

