using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace OAKProxy
{
    public static class Errors
    {
        public enum Code
        {
            Unknown,
            UnhandledException,
            NoRoute,
            NoIdentityTranslation,
            NoAuthorizationClaims,
            UnconfiguredPath
        }

        public static readonly MediaTypeHeaderValue ApplicationJson = 
            MediaTypeHeaderValue.Parse("application/json").CopyAsReadOnly();

        public static Task Handle(HttpContext context)
        {
            var exception = context.Features.Get<IExceptionHandlerFeature>()?.Error;
            if (exception != null)
            {
                context.Response.StatusCode = (int)HttpStatusCode.InternalServerError;
                context.SetErrorDetail(Code.UnhandledException, "Unhandled Exception");
            }

            return Task.CompletedTask;
        }

        public static async Task StatusPageAsync(StatusCodeContext context)
        {
            var accept = context.HttpContext.Request.GetTypedHeaders().Accept;
            bool json = accept is null || accept.Count == 0 || accept.Any(x => ApplicationJson.IsSubsetOf(x));

            string type, content;
            (Code code, string message) = context.HttpContext.GetErrorDetail();
            int status = context.HttpContext.Response.StatusCode;
            int codeNumber = (int)code;
            if (json)
            {
                type = "application/json";
                content = $"{{\"error\":{{\"source\":\"OAKProxy\",\"status\":{status},\"code\":{codeNumber},\"message\":\"{message}\"}}}}";
            }
            else
            {
                type = "text/plain";
                content = $"OAKProxy Error Status[{status}] Code[{codeNumber}] Message[{message}]";
            }

            context.HttpContext.Response.ContentType = type;
            await context.HttpContext.Response.WriteAsync(content, context.HttpContext.RequestAborted);
        }

        public static (Code Code, string Details) GetErrorDetail(this HttpContext context)
        {
            return 
                (context.Items["ErrorCode"] as Code? ?? Code.Unknown, 
                context.Items["ErrorDetails"] as string ?? "Unknown");
        }

        public static void SetErrorDetail(this HttpContext context, Code code, string details)
        {
            context.Items["ErrorCode"] = code;
            context.Items["ErrorDetails"] = details;
        }
    }
}