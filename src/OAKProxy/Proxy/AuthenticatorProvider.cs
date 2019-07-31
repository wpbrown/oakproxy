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

        public AuthenticatorProvider(IServiceProvider provider, IOptions<ProxyOptions> options)
        {
            foreach (var application in options.Value.Applications)
            {
                _authenticators[application.Name] = application.AuthenticatorBindings?.Select(bindingOptions =>
                {
                    var authenticatorOptions = options.Value.Authenticators.First(a => a.Name == bindingOptions.Name);
                    return (IAuthenticator)ActivatorUtilities.CreateInstance(provider, authenticatorOptions.ImplType, authenticatorOptions, bindingOptions);
                }).ToArray() ?? new IAuthenticator[] { } ;
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
