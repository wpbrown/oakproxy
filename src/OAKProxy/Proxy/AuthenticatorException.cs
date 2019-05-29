using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Threading.Tasks;
using static OAKProxy.Errors;

namespace OAKProxy.Proxy
{
    public class AuthenticatorException : Exception
    {
        public readonly Code Code;

        public AuthenticatorException(Code code, string message) : 
            base(message)
        {
            Code = code;
        }

        public AuthenticatorException(Code code, string message, Exception innerException) : 
            base(message, innerException)
        {
            Code = code;
        }
    }
}
