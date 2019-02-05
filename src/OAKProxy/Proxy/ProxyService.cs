using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
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
        private readonly PrincipalContext _adContext;

        public ProxyService(IOptions<OAKProxyOptions> options, IMemoryCache memoryCache)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            _options = options.Value;
            _routes = _options.ProxiedApplications.ToDictionary(x => x.Audience, x => x.Destination);
            _domainIdentityCache = memoryCache;

            if (_options.SidMatching != OKProxySidMatchingOption.Never)
            {
                _adContext = new PrincipalContext(ContextType.Domain);
            }
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
            string objectId = user.Claims.First(c => c.Type == "oid").Value;

            return _domainIdentityCache.GetOrCreate(objectId, (entry) => {
                entry.SlidingExpiration = TimeSpan.FromMinutes(10);

                string upn = user.Claims.FirstOrDefault(c => c.Type == "upn")?.Value;
                if (upn != null)
                {
                    if (_options.SidMatching != OKProxySidMatchingOption.Never)
                    {
                        var sidClaim = user.Claims.FirstOrDefault(c => c.Type == "onprem_sid");
                        if (sidClaim != null)
                        {
                            using (var principal = UserPrincipal.FindByIdentity(_adContext, IdentityType.Sid, sidClaim.Value))
                            {
                                if (principal != null)
                                {
                                    upn = principal.UserPrincipalName;
                                }
                                else
                                {
                                    return null;
                                }
                            }
                        }
                        else if (_options.SidMatching == OKProxySidMatchingOption.Only)
                        {
                            return null;
                        }
                    }
                }
                else
                {
                    upn = _options.ServicePrincipalMappings.FirstOrDefault(m => m.ObjectId == objectId)?.UserPrincipalName;
                    if (upn == null)
                        return null;
                }

                return new WindowsIdentity(upn);
            });
        }
    }
}
