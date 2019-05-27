using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAKProxy
{
    public class AzureADClaims
    {
        public const string Scope = "scp";
        public const string Roles = "roles";
        public const string ApplicationAuthType = "appidacr";
        public const string UserPrincipalName = "upn";
        public const string ObjectId = "oid";
    }
}
