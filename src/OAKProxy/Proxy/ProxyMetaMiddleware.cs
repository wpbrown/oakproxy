using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace OAKProxy.Proxy
{
    public class ProxyMetaMiddleware
    {
        public ProxyMetaMiddleware(RequestDelegate _)
        {
        }

        public async Task InvokeAsync(HttpContext context, IProxyApplicationService applicationService)
        {
            var application = applicationService.GetActiveApplication();
            if (application.HasPathMode(PathAuthOptions.AuthMode.Web))
            {
                if (context.Request.Path == "/accessdenied")
                {
                    await context.Response.WriteAsync("Access denied.");
                    return;
                }

                if (context.Request.Path == "/postloggedout")
                {
                    await context.Response.WriteAsync("Logged out.");
                    return;
                }

                // can the openid remote handler deal with this instead?
                if (context.Request.Path == "/auth/logout")
                {
                    var schemes = ProxyAuthComponents.GetAuthSchemes(application);

                    await context.SignOutAsync(schemes.CookieName, new AuthenticationProperties { RedirectUri = "/.oakproxy/postloggedout" });
                    await context.SignOutAsync(schemes.OpenIdName, new AuthenticationProperties { RedirectUri = "/.oakproxy/postloggedout" });
                    return;
                }
            }

            context.Response.StatusCode = (int)HttpStatusCode.NotFound;
        }
    }
}
