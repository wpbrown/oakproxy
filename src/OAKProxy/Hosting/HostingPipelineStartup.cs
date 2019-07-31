using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Options;
using OAKProxy.Proxy;
using System;

namespace OAKProxy.Hosting
{
    public class HostingPipelineStartup : IStartupFilter
    {
        private readonly IOptions<OakproxyServerOptions> _serverOptionsAccessor;

        public HostingPipelineStartup(IOptions<OakproxyServerOptions> serverOptionsAccessor)
        {
            _serverOptionsAccessor = serverOptionsAccessor;
        }

        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
        {
            return builder =>
            {
                if (_serverOptionsAccessor.Value.EnableHealthChecks || _serverOptionsAccessor.Value.UseAzureApplicationGateway)
                    builder.UseHealthChecks(ProxyMetaEndpoints.FullPath(ProxyMetaEndpoints.Health));

                builder.UseStatusCodePages(Errors.StatusPageAsync);
                builder.UseExceptionHandler(new ExceptionHandlerOptions { ExceptionHandler = Errors.Handle });

                if (_serverOptionsAccessor.Value.UseForwardedHeaders)
                    builder.UseForwardedHeaders();

                next(builder);
            };
        }
    }
}
