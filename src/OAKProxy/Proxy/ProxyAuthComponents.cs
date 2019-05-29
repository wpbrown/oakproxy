using Microsoft.AspNetCore.Authentication.AzureAD.UI;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAKProxy.Proxy
{
    public class ProxyAuthComponents
    {
        public static readonly string WebAuth = "web";
        public static readonly string ApiAuth = "api";

        public static readonly string WebUserRole = "user_web";
        public static readonly string ApiAppRole = "app_impersonation";
        public static readonly string ApiUserScope = "user_impersonation";

        public static readonly string CookiePrefix = ".oakproxy";
        public static readonly string AuthCookieId = "a";

        public static string GetWebPolicyName(ProxyApplication application)
        {
            return application.Name + ".openid";
        }

        public static string GetApiPolicyName(ProxyApplication application)
        {
            return application.Name + ".oauth2";
        }

        public static Schemes GetAuthSchemes(ProxyApplication application)
        {
            return new Schemes()
            {
                WebName = $"{application.Name}.{AzureADDefaults.AuthenticationScheme}",
                DisplayName = $"{application.Name}.{AzureADDefaults.DisplayName}",
                OpenIdName = $"{application.Name}.{AzureADDefaults.OpenIdScheme}",
                CookieName = $"{application.Name}.{AzureADDefaults.CookieScheme}",

                ApiName = $"{application.Name}.{AzureADDefaults.BearerAuthenticationScheme}",
                JwtBearerName = $"{application.Name}.{AzureADDefaults.JwtBearerAuthenticationScheme}",
            };
        }

        public static bool IsSchemeForApplication(string scheme, ProxyApplication application)
        {
            return scheme.StartsWith($"{application.Name}.");
        }
        
        public class Schemes
        {
            public string DisplayName { get; set; }

            public string WebName { get; set; }
            public string OpenIdName { get; set; }
            public string CookieName { get; set; }

            public string ApiName { get; set; }
            public string JwtBearerName { get; set; }
        }
    }
}
