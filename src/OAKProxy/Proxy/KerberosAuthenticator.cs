using Microsoft.ApplicationInsights.DataContracts;
using Microsoft.Extensions.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;

namespace OAKProxy.Proxy
{
    public class KerberosAuthenticator : IAuthenticator
    {
        private readonly AuthenticatorOptionsBase _options;

        public KerberosAuthenticator(AuthenticatorOptionsBase options)
        {
            _options = options;
        }

        public void Configure(HttpMessageHandlerBuilder builder)
        {
            if (builder.PrimaryHandler is HttpClientHandler handler) 
            {
                handler.UseDefaultCredentials = true;
            }
            else
            {
                throw new Exception("Failed to configure for Kerberos auth.");
            }

            builder.AdditionalHandlers.Add(new KerberosHandler() {
                Options = _options,
                IdentityService = builder.Services.GetService<KerberosIdentityService>()
            });
        }

        private class KerberosHandler : DelegatingHandler
        {
            public AuthenticatorOptionsBase Options;
            public KerberosIdentityService IdentityService;

            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                var user = request.GetUser();

                WindowsIdentity domainIdentity = IdentityService.TranslateDomainIdentity(user, Options);
                if (domainIdentity is null)
                {
                    throw new AuthenticatorException(Errors.Code.NoIdentityTranslation, "Identity could not be translated to a domain identity");
                }

                request.Properties.Add("S4uIdentity", domainIdentity);
                return base.SendAsync(request, cancellationToken);
            }
        }
    }
}

