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
    public class KerberosIdentityService
    {
        private readonly IMemoryCache _domainIdentityCache;
        private readonly PrincipalContext _adContext;
        private readonly ILogger<KerberosIdentityService> _logger;

        public KerberosIdentityService(IOptions<ApplicationOptions> options, IMemoryCache memoryCache, ILogger<KerberosIdentityService> logger)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            _domainIdentityCache = memoryCache;
            _logger = logger;

            bool hasSidMatching = !options.Value.Authenticators.All(a => a.SidMatching == SidMatchingOption.Never);

            if (hasSidMatching)
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

        public WindowsIdentity TranslateDomainIdentity(ClaimsPrincipal user, Authenticator options)
        {
            string objectId = user.Claims.First(c => c.Type == "oid").Value;

            return _domainIdentityCache.GetOrCreate(objectId, (entry) => {
                string cloudUpn = user.Claims.FirstOrDefault(c => c.Type == "upn")?.Value;
                string adUpn = null;

                if (cloudUpn != null) // User Matching
                {
                    Claim sidClaim = null;
                    if (options.SidMatching != SidMatchingOption.Never) // Sid Matching
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
                    
                    bool requireSidMatch = options.SidMatching == SidMatchingOption.Only;
                    bool sidClaimFoundFirst = options.SidMatching == SidMatchingOption.First && sidClaim != null;
                    if (adUpn == null && !requireSidMatch && !sidClaimFoundFirst)
                    {
                        adUpn = cloudUpn;
                    }
                }
                else // Application Matching
                {
                    adUpn = options.ServicePrincipalMappings.FirstOrDefault(m => m.ObjectId == objectId)?.UserPrincipalName;
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
