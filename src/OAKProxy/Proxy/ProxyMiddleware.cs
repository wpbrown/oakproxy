using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OAKProxy.Proxy;
using ProcessPrivileges;

namespace OAKProxy.Proxy
{
    public class ProxyMiddleware
    {
        private readonly ProxyService _proxyService;

        public ProxyMiddleware(RequestDelegate next, ProxyService service)
        {
            _proxyService = service;
        }

        public async Task Invoke(HttpContext context, HttpForwarder httpForwarder)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Uri destinationAppUri = _proxyService.RouteRequest(context);
            WindowsIdentity domainIdentity = _proxyService.TranslateDomainIdentity(context.User);
            await ProxyRequest(context, httpForwarder, domainIdentity, destinationAppUri);
        }

        private static async Task ProxyRequest(HttpContext context, HttpForwarder httpForwarder, WindowsIdentity domainIdentity, Uri destinationAppUri)
        {
            using (var requestMessage = CreateHttpRequestMessageFromIncomingRequest(context.Request, destinationAppUri))
            {
#if NETFX
                await ResolveHostInMessage(requestMessage);
#endif
                var proc = System.Diagnostics.Process.GetCurrentProcess();
                await WindowsIdentity.RunImpersonated(domainIdentity.AccessToken, async () =>
                {
                    using (var responseMessage = await httpForwarder.ForwardAsync(requestMessage, context.RequestAborted))
                    {
                        await CopyProxiedMessageToResponseAsync(context.Response, responseMessage, context.RequestAborted);
                    }
                });
            }
        }

        private static async Task ResolveHostInMessage(HttpRequestMessage requestMessage)
        {
            Uri originalUri = requestMessage.RequestUri;
            string originalHost = originalUri.Host;

            var builder = new UriBuilder(originalUri);
            var ip = await Dns.GetHostEntryAsync(originalUri.DnsSafeHost);
            builder.Host = ip.AddressList.First().ToString();
            requestMessage.RequestUri = builder.Uri;
        }

        private static HttpRequestMessage CreateHttpRequestMessageFromIncomingRequest(HttpRequest request, Uri destinationAppUri)
        {          
            var requestMessage = new HttpRequestMessage();
            var requestMethod = request.Method;
            if (!HttpMethods.IsGet(requestMethod) &&
                !HttpMethods.IsHead(requestMethod) &&
                !HttpMethods.IsDelete(requestMethod) &&
                !HttpMethods.IsTrace(requestMethod))
            {
                var streamContent = new StreamContent(request.Body);
                requestMessage.Content = streamContent;
            }

            // Copy the request headers
            foreach (var header in request.Headers)
            {
                if (!requestMessage.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray()) && requestMessage.Content != null)
                {
                    requestMessage.Content?.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray());
                }
            }

            var uri = new Uri(UriHelper.BuildAbsolute(destinationAppUri.Scheme, HostString.FromUriComponent(destinationAppUri), 
                destinationAppUri.AbsolutePath, request.Path, request.QueryString));
            requestMessage.Headers.Host = uri.Authority;
            requestMessage.RequestUri = uri;
            requestMessage.Method = new HttpMethod(request.Method);

            return requestMessage;
        }

        private static async Task CopyProxiedMessageToResponseAsync(HttpResponse response, HttpResponseMessage responseMessage, CancellationToken token)
        {
            const int StreamCopyBufferSize = 81920;

            if (responseMessage == null)
            {
                throw new ArgumentNullException(nameof(responseMessage));
            }

            response.StatusCode = (int)responseMessage.StatusCode;
            foreach (var header in responseMessage.Headers)
            {
                response.Headers[header.Key] = header.Value.ToArray();
            }

            foreach (var header in responseMessage.Content.Headers)
            {
                response.Headers[header.Key] = header.Value.ToArray();
            }

            // SendAsync removes chunking from the response. This removes the header so it doesn't expect a chunked response.
            response.Headers.Remove("transfer-encoding");

            using (var responseStream = await responseMessage.Content.ReadAsStreamAsync())
            {
                await responseStream.CopyToAsync(response.Body, StreamCopyBufferSize, token);
            }
        }
    }
}
