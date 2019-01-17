using Microsoft.Win32.SafeHandles;
using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;

namespace TestImpersonateAsync
{
    class Program
    {
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool LogonUser(String lpszUsername, String lpszDomain, String lpszPassword,
            int dwLogonType, int dwLogonProvider, out SafeAccessTokenHandle phToken);

        const int LOGON32_PROVIDER_DEFAULT = 0;
        const int LOGON32_LOGON_NETWORK = 3;
        static readonly ThreadLocal<Random> random = new ThreadLocal<Random>(() => new Random(Thread.CurrentThread.ManagedThreadId));

        static void Main(string[] args)
        {
            string user = Environment.UserName;
            LogonUser("test1", "localhost", "test1pass", LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, out SafeAccessTokenHandle ath1);
            LogonUser("test2", "localhost", "test2pass", LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, out SafeAccessTokenHandle ath2);
            Console.WriteLine($"Main Begin: {Environment.UserName}");
            var tasks = Enumerable.Range(1, 50).Select(x => {
                var token = x % 2 == 0 ? ath1 : ath2;
                var name = x % 2 == 0 ? "test1" : "test2";
                return WindowsIdentity.RunImpersonated(token, async () => await TestRun(x, name));
            });
            Task.Delay(500).ContinueWith(async t => await TestRun(0, user));
            Task.WaitAll(tasks.ToArray());
            Console.WriteLine($"Main End: {Environment.UserName}");
        }

        static async Task TestRun(int test, string expectUser)
        {
            TestUser(test, expectUser);
            Thread.Sleep(random.Value.Next(5, 50));
            await Task.Delay(random.Value.Next(5, 100));
            TestUser(test, expectUser);
            Thread.Sleep(random.Value.Next(5, 50));
            await Task.Delay(random.Value.Next(5, 50));
            TestUser(test, expectUser);
        }

        static void TestUser(int test, string expectUser)
        {
            var actualUser = Environment.UserName;
            Console.WriteLine($"[{test}] Actual: {actualUser} Expect: {expectUser} Thread: {Thread.CurrentThread.ManagedThreadId}");
            Trace.Assert(actualUser == expectUser);
        }
    }
}