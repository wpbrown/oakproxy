using CommandLine;
using System;
using System.Diagnostics;
using System.Net.Http;
using System.Reflection;
using System.Security.Principal;
using ProcessPrivileges;
using System.Runtime.Versioning;
#if COREFX
using System.Runtime.Loader;
#endif

namespace DemoImperClient
{
    class Program
    {
        private static void Main(string[] args)
        {
            Options o = null;
            Parser.Default.ParseArguments<Options>(args).WithParsed(x => o = x);
            if (o == null)
                return;

            var framework = Assembly.GetEntryAssembly().GetCustomAttribute<TargetFrameworkAttribute>().FrameworkName;
            Console.WriteLine("TestImper Begin.");
            Console.WriteLine($"App Runtime: {framework}");
            Console.WriteLine($"Primary User: {Environment.UserName}");

#if COREFX
            // Workaround for corefx. Assemblies fail to load during impersonation when the token 
            // impersonation level is only valid for identification.
            PreloadAssemblies();

            // This option only has meaning for corefx.
            
            AppContext.SetSwitch("System.Net.Http.UseSocketsHttpHandler", o.UseSocketHandler);
            Console.WriteLine($"UseSocketsHttpHandler: {o.UseSocketHandler}");
#endif

            // Run Test without impersonation.
            DoAsyncTest(o.TestUrl);

            // Setup impersonation.
            AdjustPrivileges(enableTcb: o.UseTcb, enableImpersonate: o.UseImpersonate);
            string requestingUpn = $"user1@{Environment.UserDomainName}";
            Console.WriteLine($"Requesting Token Name: {requestingUpn}");
            WindowsIdentity wi = new WindowsIdentity(requestingUpn);
            TokenImpersonationLevel token = wi.ImpersonationLevel;
            Console.WriteLine($"Impersonation Token Name: {wi.Name}");
            Console.WriteLine($"Impersonation Token Level: {token}");
            WindowsIdentity.RunImpersonated(wi.AccessToken, () =>
            {
                Console.WriteLine($"Impersonation User: {Environment.UserName}");
                // Run Test with impersonation.
                DoAsyncTest(o.TestUrl);
            });

            Console.WriteLine("TestImper end.");
        }

        private static void DoAsyncTest(string url)
        {
            var handler = new HttpClientHandler()
            {
                UseDefaultCredentials = true,
                UseProxy = false // Fixes access denied in WinHttpOpen call during impersonation.
            };
            var client = new HttpClient(handler);
            try
            {
                var res = client.GetAsync(url).Result;
                var data = res.Content.ReadAsStringAsync().Result;
                if (res.StatusCode == System.Net.HttpStatusCode.OK)
                    Console.WriteLine($"API Result Data: {data}");
                else
                    Console.WriteLine($"API Result Error: {res.StatusCode} ({(int)res.StatusCode})");
            }
            catch (Exception e)
            {
                Console.WriteLine("API Call Exception:");
                Console.WriteLine(e.ToString());
            }
        }

#if COREFX
        private static void PreloadAssemblies()
        {
            string runtimeAssemblyPath = System.Runtime.InteropServices.RuntimeEnvironment.GetRuntimeDirectory();
            AssemblyLoadContext.Default.LoadFromAssemblyPath($"{runtimeAssemblyPath}\\Microsoft.Win32.Primitives.dll");
            AssemblyLoadContext.Default.LoadFromAssemblyPath($"{runtimeAssemblyPath}\\System.Memory.dll");
            AssemblyLoadContext.Default.LoadFromAssemblyPath($"{runtimeAssemblyPath}\\System.Net.Http.dll");
            AssemblyLoadContext.Default.LoadFromAssemblyPath($"{runtimeAssemblyPath}\\System.Resources.ResourceManager.dll");
        }
#endif
        private static void AdjustPrivileges(bool enableTcb, bool enableImpersonate)
        {
            Process process = Process.GetCurrentProcess();

            if (enableTcb)
                process.EnablePrivilege(Privilege.TrustedComputerBase);
            else
                process.DisablePrivilege(Privilege.TrustedComputerBase);

            if (enableImpersonate)
                process.EnablePrivilege(Privilege.Impersonate);
            else
                process.DisablePrivilege(Privilege.Impersonate);

            Console.WriteLine("Current Privileges:");
            foreach (PrivilegeAndAttributes privilegeAndAttributes in process.GetPrivileges())
            {
                Privilege privilege = privilegeAndAttributes.Privilege;
                PrivilegeState privilegeState = privilegeAndAttributes.PrivilegeState;
                Console.WriteLine($"  {privilege, -20} => {privilegeState}");
            }
        }
    }

    public class Options
    {
        [Option('t', "usetcb", Required = false)]
        public bool UseTcb { get; set; }

        [Option('i', "useimpersonate", Required = false)]
        public bool UseImpersonate { get; set; }

        [Option('u', "url", Required = false, Default = "http://testapp.corp.beaglelab.space/api")]
        public string TestUrl { get; set; }

#if COREFX
        [Option('s', "usesockethandler", Required = false)]
        public bool UseSocketHandler { get; set; }
#endif
    }
}
