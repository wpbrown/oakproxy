﻿using Microsoft.ApplicationInsights.DataContracts;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;

namespace OAKProxy.Proxy
{
    public class ProxyMiddleware
    {
        private readonly IHttpClientFactory _clientFactory;
        private readonly IClaimsProviderProvider _claimsProviders;

        public ProxyMiddleware(RequestDelegate next, IHttpClientFactory clientFactory, IClaimsProviderProvider claimsProviders)
        {
            _clientFactory = clientFactory;
            _claimsProviders = claimsProviders;
        }

        public async Task Invoke(HttpContext context, IProxyApplicationService applicationService)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var application = applicationService.GetActiveApplication();
            var claimsTransforms = _claimsProviders[application.Name];
            foreach (var claimsTransform in claimsTransforms)
            {
                await claimsTransform.UpdateAsync(context.AuthenticationTicket());
            }

            var client = _clientFactory.CreateClient(application.Name);

            using (var requestMessage = CreateHttpRequestMessageFromIncomingRequest(context))
            {
                try
                {
                    using (var responseMessage = await client.SendAsync(requestMessage, context.RequestAborted))
                    {
                        await CopyProxiedMessageToResponseAsync(context.Response, responseMessage, context.RequestAborted);
                    }
                }
                catch (AuthenticatorException e)
                {
                    context.Response.StatusCode = 403;
                    context.SetErrorDetail(e.Code, e.Message);
                }
                catch (HttpRequestException e)
                {
                    if (e.InnerException is SocketException se && se.SocketErrorCode == SocketError.TimedOut) {
                        context.Response.StatusCode = 504;
                        context.SetErrorDetail(Errors.Code.NoResponse, "The downstream server did not respond.");
                    }
                    else
                    {
                        throw;
                    }
                }

                var telemetry = context.Features.Get<RequestTelemetry>();
                string authenticatorUser = AuthenticatorHandler.GetAuthenticatorProvidedUser(requestMessage);
                if (telemetry != null && authenticatorUser != null)
                {
                    telemetry.Context.User.AccountId = authenticatorUser;
                }
            }
        }

        private static readonly Uri cookieUri = new Uri("http://localhost/");

        private static HttpRequestMessage CreateHttpRequestMessageFromIncomingRequest(HttpContext context)
        {
            var request = context.Request;
            var requestMessage = new HttpRequestMessage();
            AuthenticatorHandler.RelateIncomingRequestToMessage(context, requestMessage);

            var requestMethod = request.Method;
            if (!HttpMethods.IsGet(requestMethod) &&
                !HttpMethods.IsHead(requestMethod) &&
                !HttpMethods.IsDelete(requestMethod) &&
                !HttpMethods.IsTrace(requestMethod))
            {
                var streamContent = new StreamContent(request.Body);
                requestMessage.Content = streamContent;
            }

            bool needToStripCookie = context.Request.Cookies?.Any(c => c.Key.StartsWith(ProxyAuthComponents.CookiePrefix)) ?? false;

            foreach (var header in request.Headers)
            {
                if (header.Key.Equals(HeaderNames.Host, StringComparison.InvariantCultureIgnoreCase) ||
                    header.Key.Equals(HeaderNames.Authorization, StringComparison.InvariantCultureIgnoreCase) ||
                    (needToStripCookie && header.Key.Equals(HeaderNames.Cookie, StringComparison.InvariantCultureIgnoreCase)) ||
                    header.Key.StartsWith("X-Forwarded-", StringComparison.InvariantCultureIgnoreCase) ||
                    header.Key.StartsWith("X-Original-", StringComparison.InvariantCultureIgnoreCase))
                    continue;

                if (!requestMessage.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray()) && requestMessage.Content != null)
                {
                    requestMessage.Content?.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray());
                }
            }

            if (needToStripCookie)
            {
                var cookies = CreateCookieHeaderValue(request.Cookies.Where(c => !c.Key.StartsWith(ProxyAuthComponents.CookiePrefix)));
                if (cookies != null)
                {
                    requestMessage.Headers.Add(HeaderNames.Cookie, cookies);
                }
            }

            var uri = new Uri(UriHelper.BuildRelative(null, request.Path, request.QueryString), UriKind.Relative);
            requestMessage.RequestUri = uri;
            requestMessage.Method = new HttpMethod(request.Method);
            requestMessage.Headers.TryAddWithoutValidation(ForwardedHeadersDefaults.XForwardedHostHeaderName, context.Request.Host.ToUriComponent());
            requestMessage.Headers.TryAddWithoutValidation(ForwardedHeadersDefaults.XForwardedProtoHeaderName, context.Request.Scheme);
            requestMessage.Headers.TryAddWithoutValidation(ForwardedHeadersDefaults.XForwardedForHeaderName, context.Connection.RemoteIpAddress.ToString());

            return requestMessage;
        }

        private static string CreateCookieHeaderValue(IEnumerable<KeyValuePair<string,string>> cookies)
        {
            var container = new CookieContainer();
            foreach (var cookie in cookies)
            {
                container.Add(cookieUri, new Cookie(cookie.Key, cookie.Value));
            }

            return container.Count > 0 ? container.GetCookieHeader(cookieUri) : null;
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
