using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;

namespace OAKProxy.Proxy
{
    public class ProxyService
    {
        private readonly OAKProxyOptions _options;
        private readonly Dictionary<string, Uri> _routes;
        private readonly IMemoryCache _domainIdentityCache;

        public ProxyService(IOptions<OAKProxyOptions> options, IMemoryCache memoryCache)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            _options = options.Value;
            _routes = _options.ProxiedApplications.ToDictionary(x => x.Audience, x => x.Destination);
            _domainIdentityCache = memoryCache;
        }

        internal Uri RouteRequest(HttpContext context)
        {
            try
            {
                var audience = context.User.Claims.First(x => x.Type == "aud").Value;
                return _routes[audience];
            }
            catch (InvalidOperationException e)
            {
                throw new InvalidOperationException("Failed to find audience claim.", e);
            }
            catch (KeyNotFoundException e)
            {
                throw new InvalidOperationException("Route not found for given audience.", e);
            }
        }

        internal WindowsIdentity TranslateDomainIdentity(ClaimsPrincipal user)
        {
            string upn = user.Identity.Name;
            return _domainIdentityCache.GetOrCreate(upn, (entry) => {
                entry.SlidingExpiration = TimeSpan.FromMinutes(10);
                return new WindowsIdentity(upn);
            });
        }
    }
}
