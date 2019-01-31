﻿using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;

namespace OAKProxy.Proxy
{
    internal class JwtBearerConfiguration : IPostConfigureOptions<JwtBearerOptions>
    {
        private readonly OAKProxyOptions _proxyOptions;

        public JwtBearerConfiguration(IOptions<OAKProxyOptions> proxyOptions)
        {
            _proxyOptions = proxyOptions.Value;
        }

        public void PostConfigure(string name, JwtBearerOptions options)
        {
            options.TokenValidationParameters.ValidAudiences =
                _proxyOptions.ProxiedApplications.Select(x => x.Audience).ToArray();

            options.SecurityTokenValidators.Clear();
            options.SecurityTokenValidators.Add(new JwtSecurityTokenHandler
            {
                MapInboundClaims = false
            });
        }
    }
}
