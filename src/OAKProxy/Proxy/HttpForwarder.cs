using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace OAKProxy.Proxy
{
    public class HttpForwarder
    {
        private HttpClient Client { get; }

        public HttpForwarder(HttpClient client)
        {
            Client = client;
        }

        public async Task<HttpResponseMessage> ForwardAsync(HttpRequestMessage requestMessage, System.Security.Principal.WindowsIdentity domainIdentity, CancellationToken token)
        {
            requestMessage.Properties.Add("S4uIdentity", domainIdentity);
            return await Client.SendAsync(requestMessage, HttpCompletionOption.ResponseHeadersRead, token);
        }
    }
}
