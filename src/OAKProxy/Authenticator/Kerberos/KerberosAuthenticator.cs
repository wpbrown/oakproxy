using Microsoft.Extensions.DependencyInjection;
using System;
using System.Linq;
using System.Net;
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
            EnableUseDefaultKerberosCredentials(builder.PrimaryAuthenticatedHandler);
            
            if (_bindingOptions.SendAnonymousRequestAsService)
            {
                EnableUseDefaultKerberosCredentials(builder.PrimaryAnonymousHandler);
            }

            builder.AuthenticatorHandlers.Add(new KerberosHandler() {
                Options = _options,
                IdentityService = builder.Services.GetService<KerberosIdentityService>()
            });
        }

        private static void EnableUseDefaultKerberosCredentials(SocketsHttpHandler handler)
        {
            handler.Credentials = CredentialCache.DefaultCredentials;

            // We must disable connection pooling when using Kerberos, due to a bug in corefx.
            // This is a temporary workaround until a better solution is implemeneted.
            // https://github.com/dotnet/corefx/issues/39621
            handler.MaxConnectionsPerServer = int.MaxValue;
            handler.PooledConnectionLifetime = TimeSpan.Zero;
        }

        private class KerberosHandler : AuthenticatorHandler
        {
            public AuthenticatorOptionsBase Options;
            public KerberosIdentityService IdentityService;

            protected override Task<HttpResponseMessage> SendAsyncAuthenticator(AuthenticatorSendContext context, CancellationToken cancellationToken)
            {
                var upnClaim = context.AuthenticatedUser.Claims.FirstOrDefault(c => c.Type == Options.DomainUpnClaimName);
                string domainUserPrincipalName = upnClaim?.Value;
                if (String.IsNullOrEmpty(domainUserPrincipalName))
                {
                    throw new AuthenticatorException(Errors.Code.DomainUpnClaimMissing, "The domain identity claim is missing.");
                }

                WindowsIdentity domainIdentity = IdentityService.LogonUser(domainUserPrincipalName);
                if (domainIdentity is null)
                {
                    throw new AuthenticatorException(Errors.Code.DomainLogonFailed, "The domain identity could not be logged on to the domain.");
                }

                context.Message.Properties.Add("S4uIdentity", domainIdentity);
                context.AuthenticatorProvidedUser = domainUserPrincipalName;
                return base.SendAsyncAuthenticator(context, cancellationToken);
            }
        }
    }
}

