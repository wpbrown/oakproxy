using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading.Tasks;

namespace OAKProxy.Proxy
{
    internal class JwtBearerConfiguration : IPostConfigureOptions<JwtBearerOptions>
    {
        private readonly OAKProxyOptions _proxyOptions;

        public JwtBearerConfiguration(IOptions<OAKProxyOptions> proxyOptions)
        {
            _proxyOptions = proxyOptions.Value;
        }

        public void PostConfigure(string name, JwtBearerOptions options)
        {
            options.TokenValidationParameters.ValidAudiences =
                _proxyOptions.ProxiedApplications.Select(x => x.ClientId).ToArray();

            options.SecurityTokenValidators.Clear();
            options.SecurityTokenValidators.Add(new JwtSecurityTokenHandler
            {
                MapInboundClaims = false
            });

            options.Events = new JwtBearerEvents
            {
                OnChallenge = HandleChallenge
            };
        }

        public static Task HandleChallenge(JwtBearerChallengeContext context)
        {
            if (context.AuthenticateFailure is SecurityTokenInvalidAudienceException exception)
            {
                context.Response.StatusCode = 502;
                context.HttpContext.SetErrorDetail(Errors.Code.NoRoute, $"No route for this request (unknown audience: {exception.InvalidAudience})");
                context.HandleResponse();
            }
            
            return Task.CompletedTask;
        }
    }
}
