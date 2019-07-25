using Microsoft.Win32.SafeHandles;
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security;

namespace OAKProxy.ProcessPrivileges
{
    public static class ThreadExtensions
    { 
        public static bool IsImpersonating()
        {
            using AccessTokenHandle accessTokenHandle = new AccessTokenHandle(
                new ThreadHandle(NativeMethods.GetCurrentThread(), false), TokenAccessRights.Query);
            return !accessTokenHandle.IsInvalid;
        }
    }

    public sealed class AccessTokenHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal AccessTokenHandle(ThreadHandle threadHandle, TokenAccessRights tokenAccessRights)
            : base(true)
        {
            if (!NativeMethods.OpenThreadToken(threadHandle, tokenAccessRights, true, ref handle))
            {
                var error = Marshal.GetLastWin32Error();
                if (error == NativeMethods.ErrorNoToken)
                {
                    SetHandleAsInvalid();
                }
                else
                {
                    throw new Win32Exception(error);
                }
            }
        }

        protected override bool ReleaseHandle()
        {
            if (!NativeMethods.CloseHandle(handle))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            return true;
        }
    }

    public sealed class ThreadHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal ThreadHandle(IntPtr threadHandle, bool ownsHandle)
            : base(ownsHandle)
        {
            handle = threadHandle;
        }

        protected override bool ReleaseHandle()
        {
            if (!NativeMethods.CloseHandle(handle))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            return true;
        }
    }

    [Flags]
    public enum TokenAccessRights
    {
        Query = 8
    }

    internal static class NativeMethods
    {
        internal const int ErrorInsufficientBuffer = 122;
        internal const int ErrorNoToken = 0x3f0;
        private const string AdvApi32 = "advapi32.dll";
        private const string Kernel32 = "kernel32.dll";

        [DllImport(Kernel32, SetLastError = true),
        SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseHandle(
            [In] IntPtr handle);

        [DllImport(AdvApi32, SetLastError = true),
        SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool OpenThreadToken(
            [In] ThreadHandle processHandle,
            [In] TokenAccessRights desiredAccess,
            [In] bool openAsSelf,
            [In, Out] ref IntPtr tokenHandle);

        [DllImport(Kernel32, SetLastError = true),
        SuppressUnmanagedCodeSecurity]
        internal static extern IntPtr GetCurrentThread();
    }
}