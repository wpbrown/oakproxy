using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using ProcessPrivileges;
using System.Diagnostics;

namespace OAKProxy
{
    public class Program
    {
        public static void Main(string[] args)
        {
#if COREFX
            Process process = Process.GetCurrentProcess();
            process.EnablePrivilege(Privilege.TrustedComputerBase);
#endif
            CreateWebHostBuilder(args).Build().Run();
        }

        private static IWebHostBuilder CreateWebHostBuilder(string[] args)
        {
            return WebHost.CreateDefaultBuilder(args)
#if COREFX
                // Not needed with TCB priv
                //.UseSetting(WebHostDefaults.HostingStartupAssembliesKey, "Microsoft.Win32.Primitives;System.Memory;System.Net.Http;System.Resources.ResourceManager")
#endif
                .UseStartup<Startup>()

            ;
        }
    }
}
