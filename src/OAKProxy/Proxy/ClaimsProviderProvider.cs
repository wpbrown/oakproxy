using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;

namespace OAKProxy.Proxy
{
    public interface IClaimsProviderProvider
    {
        IEnumerable<IClaimsProvider> this[string application]
        {
            get;
        }
    }

    public class ClaimsProviderProvider : IClaimsProviderProvider
    {
        private readonly Dictionary<string, IEnumerable<IClaimsProvider>> _authenticators = new Dictionary<string, IEnumerable<IClaimsProvider>>();

        public ClaimsProviderProvider(IServiceProvider provider, IOptions<ProxyOptions> options)
        {
            foreach (var application in options.Value.Applications)
            {
                _authenticators[application.Name] = application.ClaimsProviderBindings?.Select(bindingOptions =>
                {
                    var providerOptions = options.Value.ClaimsProviders.First(a => a.Name == bindingOptions.Name);
                    return (IClaimsProvider)ActivatorUtilities.CreateInstance(provider, providerOptions.ImplType, providerOptions, bindingOptions);
                }).ToArray() ?? new IClaimsProvider[] { };
            }
        }

        public IEnumerable<IClaimsProvider> this[string applicationName]
        {
            get
            {
                return _authenticators[applicationName];
            }
        }
    }
}