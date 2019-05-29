using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;

namespace OAKProxy.Proxy
{
    public static class HttpRequestMessageExtensions
    {
        public static ClaimsPrincipal GetUser(this HttpRequestMessage message)
        {
            return message.Properties["_request_user"] as ClaimsPrincipal;
        }

        public static void SetUser(this HttpRequestMessage message, ClaimsPrincipal user)
        {
            message.Properties.Add("_request_user", user);
        }

        public static string GetAuthenticatorUser(this HttpRequestMessage message)
        {
            message.Properties.TryGetValue("_authenticator_user", out object user);
            return user as string;
        }

        public static void SetAuthenticatorUser(this HttpRequestMessage message, string user)
        {
            message.Properties.Add("_authenticator_user", user);
        }
    }
}
