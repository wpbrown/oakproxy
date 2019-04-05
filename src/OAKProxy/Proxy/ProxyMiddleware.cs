using Microsoft.ApplicationInsights.DataContracts;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using System;
using System.Linq;
using System.Net.Http;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;

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
            
            Uri destinationAppUri = _proxyService.RouteRequest(context.User);
            if (destinationAppUri is null)
            {
                context.Response.StatusCode = 502;
                context.SetErrorDetail(Errors.Code.NoRoute, "No route for this request");
                return;
            }

            WindowsIdentity domainIdentity = _proxyService.TranslateDomainIdentity(context.User);
            if (domainIdentity is null)
            {
                context.Response.StatusCode = 403;
                context.SetErrorDetail(Errors.Code.NoIdentityTranslation, "Identity could not be translated to a domain identity");
                return;
            }

            var telemetry = context.Features.Get<RequestTelemetry>();
            if (telemetry != null)
            {
                telemetry.Context.User.AccountId = domainIdentity.Name;
            }

            await ProxyRequest(context, httpForwarder, domainIdentity, destinationAppUri);
        }

        private static async Task ProxyRequest(HttpContext context, HttpForwarder httpForwarder, WindowsIdentity domainIdentity, Uri destinationAppUri)
        {
            using (var requestMessage = CreateHttpRequestMessageFromIncomingRequest(context.Request, destinationAppUri))
            {
                using (var responseMessage = await httpForwarder.ForwardAsync(requestMessage, domainIdentity, context.RequestAborted))
                {
                    await CopyProxiedMessageToResponseAsync(context.Response, responseMessage, context.RequestAborted);
                }
            }
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
            const int StreamCopyBufferSize = 131072;

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
