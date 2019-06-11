using Microsoft.AspNetCore.Authentication;
using System.Threading.Tasks;

namespace OAKProxy.Proxy
{
    public interface IClaimsProvider
    {
        Task UpdateAsync(AuthenticationTicket ticket);
    }
}
