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
        private readonly ILogger<KerberosIdentityService> _logger;

        public KerberosIdentityService(IMemoryCache memoryCache, ILogger<KerberosIdentityService> logger)
        {
            _domainIdentityCache = memoryCache;
            _logger = logger;
        }

        public WindowsIdentity LogonUser(string userPrincipalName)
        {
            if (String.IsNullOrEmpty(userPrincipalName))
            {
                throw new ArgumentNullException(nameof(userPrincipalName), "Can't logon a user with a null or empty identifier.");
            }

            return _domainIdentityCache.GetOrCreate(userPrincipalName, (entry) => 
            {
                try
                {
                    var identity = new WindowsIdentity(userPrincipalName);
                    entry.SlidingExpiration = TimeSpan.FromMinutes(10);
                    return identity;
                }
                catch (Exception exception)
                {
                    _logger.LogError(exception, "Failed to logon '{userPrincipalName}' to the domain.", userPrincipalName);
                }

                // Retry logon for this objectId in 1 minute
                entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(1);
                return null;
            });
        }
    }
}
