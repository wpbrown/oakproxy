using Microsoft.Extensions.DependencyInjection;
using System;

namespace OAKProxy.Proxy
{
    public static class ProxyServiceCollectionExtensions
    {
        public static IServiceCollection AddProxy(this IServiceCollection services)
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            return services.AddSingleton<KerberosIdentityService>();
        }
    }
}
