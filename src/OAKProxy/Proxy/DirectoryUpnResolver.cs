using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace OAKProxy.Proxy
{
    public class DirectoryUpnResolver : IClaimsProvider
    {
        private readonly IMemoryCache _directoryResultCache;
        private readonly PrincipalContext _adContext;
        private readonly ILogger<DirectoryUpnResolver> _logger;
        private readonly ClaimsProviderOptionsBase _options;

        public DirectoryUpnResolver(ClaimsProviderOptionsBase options, ClaimsProviderBindingOptionsBase _, ILogger<DirectoryUpnResolver> logger, IMemoryCache memoryCache)
        {
            _logger = logger;
            _directoryResultCache = memoryCache;
            _options = options;

            if (options.SidMatching != SidMatchingOption.Never)
            {
                try
                {
                    var type = options.DirectoryServerType == DirectoryServerType.CurrentDomain ? 
                        ContextType.Domain : ContextType.ApplicationDirectory;
                    _adContext = String.IsNullOrEmpty(options.DirectoryServerName) ?
                        new PrincipalContext(type) : String.IsNullOrEmpty(options.DirectoryServerUsername) ?
                        new PrincipalContext(type, options.DirectoryServerName) :
                        new PrincipalContext(type, options.DirectoryServerName, options.DirectoryServerUsername, options.DirectoryServerPassword); 
                }
                catch (Exception)
                {
                    _logger.LogCritical("Failed to connect to the directory server for SID matching.");
                    throw;
                }
            }
        }

        public Task UpdateAsync(AuthenticationTicket ticket)
        {
            string anchorKey = _options.IdentityProviderAnchorClaimName;
            string anchorValue = 
                ticket.Principal.Claims.First(c => c.Type == anchorKey).Value +
                "." + 
                ticket.AuthenticationScheme;

            var userPrincipalName = _directoryResultCache.GetOrCreate(anchorValue, (entry) => {
                var inboundUserClaims = ticket.Principal.Claims;
                string inboundUpn = inboundUserClaims.FirstOrDefault(c => c.Type == _options.IdentityProviderUserClaimName)?.Value;
                string directoryUpn = null;

                if (inboundUpn != null) // User Matching
                {
                    Claim sidClaim = null;
                    if (_options.SidMatching != SidMatchingOption.Never) // Sid Matching
                    {
                        sidClaim = inboundUserClaims.FirstOrDefault(c => c.Type == _options.DirectorySidClaimName);
                        if (sidClaim != null)
                        {
                            using (var principal = UserPrincipal.FindByIdentity(_adContext, IdentityType.Sid, sidClaim.Value))
                            {
                                if (principal != null)
                                {
                                    directoryUpn = principal.UserPrincipalName;
                                }
                            }
                        }
                    }

                    bool requireSidMatch = _options.SidMatching == SidMatchingOption.Only;
                    bool sidClaimFoundFirst = _options.SidMatching == SidMatchingOption.First && sidClaim != null;
                    if (directoryUpn == null && !requireSidMatch && !sidClaimFoundFirst)
                    {
                        directoryUpn = inboundUpn;
                    }
                }
                else // Application Matching
                {
                    string appMappingKey = _options.IdentityProviderApplicationClaimName;
                    string appMappingValue = inboundUserClaims.FirstOrDefault(c => c.Type == appMappingKey)?.Value;
                    if (String.IsNullOrEmpty(appMappingValue))
                    {
                        _logger.LogError("Application with anchor {AnchorKey}='{AnchorValue}' is missing the mapping claim '{AppMappingClaim}'.", anchorKey, anchorValue, appMappingKey);
                    }
                    else
                    {
                        directoryUpn = _options.ServicePrincipalMappings.FirstOrDefault(m => m.ObjectId == appMappingValue)?.UserPrincipalName;
                        if (directoryUpn is null)
                            _logger.LogError("Failed to translate application with mapping key {AppMappingClaim}='{AppMappingValue}' to a directory UPN.", appMappingKey, appMappingValue);
                        else
                            _logger.LogDebug("Translated application with mapping key {AppMappingClaim}='{AppMappingValue}' to a directory UPN '{UPN}'.", appMappingKey, appMappingValue, directoryUpn);
                    }
                }

                if (directoryUpn != null)
                {
                    return directoryUpn;
                }

                // Retry resolving this objectId in 1 minute
                entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(1);
                return null;
            });

            if (userPrincipalName != null)
            {
                var identity = (ClaimsIdentity)ticket.Principal.Identity;
                identity.AddClaim(new Claim("onprem_upn", userPrincipalName));
            }

            return Task.CompletedTask;
        }
    }
}
