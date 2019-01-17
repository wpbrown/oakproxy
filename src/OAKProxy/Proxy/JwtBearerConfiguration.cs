using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using System.Linq;

namespace OAKProxy.Proxy
{
    internal class JwtBearerConfiguration : IPostConfigureOptions<JwtBearerOptions>
    {
        private readonly OKProxyOptions _proxyOptions;

        public JwtBearerConfiguration(IOptions<OKProxyOptions> proxyOptions)
        {
            _proxyOptions = proxyOptions.Value;
        }

        public void PostConfigure(string name, JwtBearerOptions options)
        {
            options.TokenValidationParameters.ValidAudiences = 
                _proxyOptions.ProxiedApplications.Select(x => x.Audience).ToArray();
        }
    }
}
