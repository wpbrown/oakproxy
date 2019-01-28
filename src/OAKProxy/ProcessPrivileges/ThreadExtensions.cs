using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security.Permissions;

namespace ProcessPrivileges
{
    public static class ThreadExtensions
    { 
        public static bool IsImpersonating()
        {
            using (AccessTokenHandle accessTokenHandle = new AccessTokenHandle(
                new ThreadHandle(NativeMethods.GetCurrentThread(), false), TokenAccessRights.Query))
            {
                return !accessTokenHandle.IsInvalid;
            }
        }
    }
}