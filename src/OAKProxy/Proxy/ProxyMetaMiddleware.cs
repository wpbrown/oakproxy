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
                if (context.Request.Path == ProxyMetaEndpoints.AccessDenied)
                {
                    await context.Response.WriteAsync("Access denied.");
                    return;
                }

                if (context.Request.Path == ProxyMetaEndpoints.PostSignedOutCallback)
                {
                    await context.Response.WriteAsync("Logged out.");
                    return;
                }

                if (context.Request.Path == ProxyMetaEndpoints.UserSignOut)
                {
                    var schemes = ProxyAuthComponents.GetAuthSchemes(application);

                    var properties = new AuthenticationProperties
                    {
                        RedirectUri = ProxyMetaEndpoints.FullPath(ProxyMetaEndpoints.PostSignedOutCallback)
                    };
                    await context.SignOutAsync(schemes.CookieName);
                    await context.SignOutAsync(schemes.OpenIdName, properties);
                    return;
                }
            }

            context.Response.StatusCode = (int)HttpStatusCode.NotFound;
        }
    }

    public static class ProxyMetaEndpoints
    {
        public static readonly PathString PathBase = "/.oakproxy";
        public static readonly PathString AuthenticatedPathBase = "/auth";

        public static readonly PathString AccessDenied = "/accessdenied";
        public static readonly PathString SignInCallback = "/login";
        public static readonly PathString SignedOutCallback = "/loggedout";
        public static readonly PathString PostSignedOutCallback = "/postloggedout";
        public static readonly PathString RemoteSignOut = "/logout";
        public static readonly PathString UserSignOut = "/auth/logout";
        public static readonly PathString Health = "/health";

        public static PathString FullPath(PathString endpoint)
        {
            return PathBase.Add(endpoint);
        }
    }
}
