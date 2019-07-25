using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using OAKProxy.PolicyEvaluator;
using System.Threading.Tasks;

namespace OAKProxy.Proxy
{
    public static class ProxyStartupExtensions
    {
        public static IServiceCollection AddOakproxy(this IServiceCollection services, ProxyOptions proxyOptions)
        {
            var builder = new ProxyServiceBuilder(proxyOptions);
            builder.ConfigureAuthentication(services);
            builder.ConfigureAuthorization(services);
            builder.ConfigureProxy(services);
            return services;
        }

        public static IApplicationBuilder UseOakproxy(this IApplicationBuilder builder)
        {
            var authenticatorWarmup = Task.Run(() => builder.ApplicationServices.GetService<IAuthenticatorProvider>());

            builder.UseHostFiltering();
            builder.UseAuthentication();
            builder.Map(ProxyMetaEndpoints.PathBase, ConfigureMetaPath);
            builder.UsePolicyEvaluation();
            builder.RunProxy();

            authenticatorWarmup.Wait();

            return builder;
        }

        private static void ConfigureMetaPath(IApplicationBuilder builder)
        {
            builder.UseWhen(
                context => context.Request.Path.StartsWithSegments(ProxyMetaEndpoints.AuthenticatedPathBase),
                whenBuilder => whenBuilder.UsePolicyEvaluation());
            builder.RunProxyMeta();
        }
    }
}
