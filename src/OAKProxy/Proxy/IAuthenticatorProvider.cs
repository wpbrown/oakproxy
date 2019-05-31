using System.Collections.Generic;

namespace OAKProxy.Proxy
{
    public interface IAuthenticatorProvider
    {
        IEnumerable<IAuthenticator> this[string application]
        {
            get;
        }
    }
}