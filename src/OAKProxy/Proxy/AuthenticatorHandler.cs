using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace OAKProxy.Proxy
{
    public class AuthenticatorHandler : DelegatingHandler
    {
        internal ExposingHandler AnonymousHandler;
        private volatile bool _disposed = false;
        private bool _handleAnonymous = false;

        public AuthenticatorHandler(bool handleAnonymous = false)
        {
            _handleAnonymous = handleAnonymous;
        }

        protected sealed override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            bool isAnonymousRequest = !request.GetUser().Identity.IsAuthenticated;

            if (!_handleAnonymous && isAnonymousRequest)
            {
                return SendAsyncBranching(request, cancellationToken);
            }
            else
            {
                return SendAsyncAuthenticator(request, cancellationToken);
            }
        }

        protected virtual Task<HttpResponseMessage> SendAsyncAuthenticator(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return SendAsyncBranching(request, cancellationToken);
        }

        private Task<HttpResponseMessage> SendAsyncBranching(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            bool isLastAuthenticator = AnonymousHandler != null;
            bool isAnonymousRequest = !request.GetUser().Identity.IsAuthenticated;

            if (isLastAuthenticator && isAnonymousRequest)
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
    }
}
