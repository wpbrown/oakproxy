using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAKProxy
{
    public static class HttpContextExtensions
    {
        public const string AuthenticationTicketItemName = ".oakproxy.AuthenticationTicket";

        public static AuthenticationTicket AuthenticationTicket(this HttpContext context) =>
            (AuthenticationTicket)context.Items[AuthenticationTicketItemName];

        public static void AuthenticationTicket(this HttpContext context, AuthenticationTicket ticket) =>
            context.Items.Add(AuthenticationTicketItemName, ticket);
    }
}
