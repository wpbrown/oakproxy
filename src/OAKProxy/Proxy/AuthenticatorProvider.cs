using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAKProxy.Proxy
{
    public class AuthenticatorProvider : IAuthenticatorProvider
    {
        private readonly Dictionary<string, IEnumerable<IAuthenticator>> _authenticators = new Dictionary<string, IEnumerable<IAuthenticator>>();

        public AuthenticatorProvider(IServiceProvider provider, IOptions<ApplicationOptions> options)
        {
            // Per Application Authenticator instances are possible in the future. None currently have
            // binding configuration so we just always do single instance.
            var singleInstances = new Dictionary<string, IAuthenticator>();

            foreach (var application in options.Value.Applications)
            {
                _authenticators[application.Name] = application.AuthenticatorBindings.Select(b =>
                {
                    if (!singleInstances.TryGetValue(b.Name, out var authenticator))
                    {
                        var authenticatorOptions = options.Value.Authenticators.First(a => a.Name == b.Name);
                        authenticator = (IAuthenticator)ActivatorUtilities.CreateInstance(provider, authenticatorOptions.ImplType, authenticatorOptions);
                        singleInstances[b.Name] = authenticator;
                    }
                    return authenticator;
                }).ToArray();
            }
        }

        public IEnumerable<IAuthenticator> this[string applicationName]
        {
            get
            {
                return _authenticators[applicationName];
            }
        }
    }
}
