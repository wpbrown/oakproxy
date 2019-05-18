using Microsoft.AspNetCore.Authentication.AzureAD.UI;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
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
        private readonly ILogger<ProxyService> _logger;

        public ProxyService(IOptions<OAKProxyOptions> options, IMemoryCache memoryCache, ILogger<ProxyService> logger)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            _options = options.Value;
            _routes = _options.ProxiedApplications.ToDictionary(x => x.ClientId, x => x.Destination);
            _domainIdentityCache = memoryCache;
            _logger = logger;

            if (_options.SidMatching != OKProxySidMatchingOption.Never)
            {
                try
                {
                    _adContext = new PrincipalContext(ContextType.Domain);
                }
                catch (Exception)
                {
                    _logger.LogCritical("Failed to connect to the domain for SID matching.");
                    throw;
                }
                
            }
        }

        internal Uri RouteRequest(ClaimsPrincipal user)
        {
            var audience = user.Claims.First(x => x.Type == "aud").Value;
            _routes.TryGetValue(audience, out Uri uri);
            return uri;
        }

        internal string GetActiveApplication(string host)
        {
            return _options.ProxiedApplications.First(x => x.Host == host).Name;
        }

        internal WindowsIdentity TranslateDomainIdentity(ClaimsPrincipal user)
        {
            string objectId = user.Claims.First(c => c.Type == "oid").Value;

            return _domainIdentityCache.GetOrCreate(objectId, (entry) => {
                string cloudUpn = user.Claims.FirstOrDefault(c => c.Type == "upn")?.Value;
                string adUpn = null;

                if (cloudUpn != null) // User Matching
                {
                    Claim sidClaim = null;
                    if (_options.SidMatching != OKProxySidMatchingOption.Never) // Sid Matching
                    {
                        sidClaim = user.Claims.FirstOrDefault(c => c.Type == "onprem_sid");
                        if (sidClaim != null)
                        {
                            using (var principal = UserPrincipal.FindByIdentity(_adContext, IdentityType.Sid, sidClaim.Value))
                            {
                                if (principal != null)
                                {
                                    adUpn = principal.UserPrincipalName;
                                }
                            }
                        }
                    }
                    
                    bool requireSidMatch = _options.SidMatching == OKProxySidMatchingOption.Only;
                    bool sidClaimFoundFirst = _options.SidMatching == OKProxySidMatchingOption.First && sidClaim != null;
                    if (adUpn == null && !requireSidMatch && !sidClaimFoundFirst)
                    {
                        adUpn = cloudUpn;
                    }
                }
                else // Application Matching
                {
                    adUpn = _options.ServicePrincipalMappings.FirstOrDefault(m => m.ObjectId == objectId)?.UserPrincipalName;
                    if (adUpn is null)
                        _logger.LogError("Failed to translate application ObjectId '{ObjectId}' to an AD UPN.", objectId);
                    else
                        _logger.LogDebug("Translated application ObjectId '{ObjectId}' to AD UPN '{AdUpn}'.", objectId, adUpn);
                }
                
                if (adUpn != null)
                {
                    try
                    {
                        var identity = new WindowsIdentity(adUpn);
                        entry.SlidingExpiration = TimeSpan.FromMinutes(10);
                        return identity;
                    }
                    catch (Exception e)
                    {
                        _logger.LogError(e, "Translated AD UPN '{AdUpn}', but it failed to logon.", adUpn);
                    }
                }

                // Retry logon for this objectId in 1 minute
                entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(1);
                return null;
            });
        }
    }
}
