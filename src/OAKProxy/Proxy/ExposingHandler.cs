using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace OAKProxy.Proxy
{
    public class ExposingHandler : DelegatingHandler
    { 
        public ExposingHandler(HttpMessageHandler innerHandler) : base(innerHandler)
        {
        }

        internal Task<HttpResponseMessage> ExposedSendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return this.SendAsync(request, cancellationToken);
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return base.SendAsync(request, cancellationToken);
        }
    }
}
