using Microsoft.ApplicationInsights.Channel;
using Microsoft.ApplicationInsights.DataContracts;
using Microsoft.ApplicationInsights.Extensibility;
using Microsoft.AspNetCore.Http;
using OAKProxy.Proxy;

namespace OAKProxy.Hosting
{
    public class OakproxyTelemetryProcessor : ITelemetryProcessor
    {
        private ITelemetryProcessor _next { get; set; }
        private static readonly PathString _healthPath = ProxyMetaEndpoints.FullPath(ProxyMetaEndpoints.Health);

        public OakproxyTelemetryProcessor(ITelemetryProcessor next)
        {
            _next = next;
        }

        public void Process(ITelemetry item)
        {
            if (item is RequestTelemetry request)
            {
                if (request.Url.LocalPath == _healthPath)
                    return;
            }
            _next.Process(item);
        }
    }
}
