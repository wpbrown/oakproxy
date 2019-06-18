using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace OAKProxy.Proxy
{
    public class AuthenticatorHandler : DelegatingHandler
    {
        internal ExposingHandler AnonymousHandler;
        private volatile bool _disposed = false;
        private readonly bool _handleAnonymous = false;

        public AuthenticatorHandler(bool handleAnonymous = false)
        {
            _handleAnonymous = handleAnonymous;
        }

        protected sealed override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            bool userIsAuthenticated = UserIsAuthenticated(request);
            if (!_handleAnonymous && !userIsAuthenticated)
            {
                return SendAsyncBranching(request, cancellationToken);
            }
            else
            {
                var context = new AuthenticatorSendContext() {
                    Message = request,
                    AuthenticatedUser = userIsAuthenticated ? GetTicket(request).Principal : null,
                    AuthenticationProperties = userIsAuthenticated ? GetTicket(request).Properties : null
                };
                return SendAsyncAuthenticator(context, cancellationToken);
            }
        }

        protected virtual Task<HttpResponseMessage> SendAsyncAuthenticator(AuthenticatorSendContext context, CancellationToken cancellationToken)
        {
            return SendAsyncBranching(context.Message, cancellationToken);
        }

        private Task<HttpResponseMessage> SendAsyncBranching(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            bool isLastAuthenticator = AnonymousHandler != null;

            if (isLastAuthenticator && !UserIsAuthenticated(request))
            {
                return AnonymousHandler.ExposedSendAsync(request, cancellationToken);
            }
            else
            {
                return base.SendAsync(request, cancellationToken);
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && !_disposed)
            {
                _disposed = true;
                if (AnonymousHandler != null)
                {
                    AnonymousHandler.Dispose();
                }
            }

            base.Dispose(disposing);
        }

        private static bool UserIsAuthenticated(HttpRequestMessage message)
        {
            return GetTicket(message)?.Principal.Identity.IsAuthenticated ?? false;
        }

        private static AuthenticationTicket GetTicket(HttpRequestMessage message)
        {
            return (AuthenticationTicket)message.Properties[HttpContextExtensions.AuthenticationTicketItemName];
        }

        internal static void RelateIncomingRequestToMessage(HttpContext request, HttpRequestMessage message)
        {
            message.Properties.Add(HttpContextExtensions.AuthenticationTicketItemName, request.AuthenticationTicket());
        }

        internal static string GetAuthenticatorProvidedUser(HttpRequestMessage message)
        {
            return message.Properties.TryGetValue(".oakproxy.AuthenticatorProvidedUser", out object user) ? (string)user : null;
        }
    }

    public class AuthenticatorSendContext
    {
        public HttpRequestMessage Message { get; internal set; }

        public ClaimsPrincipal AuthenticatedUser { get; internal set; }

        public AuthenticationProperties AuthenticationProperties { get; internal set; }

        public string AuthenticatorProvidedUser
        {
            get { return AuthenticatorHandler.GetAuthenticatorProvidedUser(Message); }
            set { Message.Properties.Add(".oakproxy.AuthenticatorProvidedUser", value); }
        }
    }
}
