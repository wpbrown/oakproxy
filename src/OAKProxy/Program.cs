﻿using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.WindowsServices;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.EventLog;
using OAKProxy.Logging;
using OAKProxy.Proxy;
using ProcessPrivileges;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;

namespace OAKProxy
{
    public class Program
    {
        public static void Main(string[] args)
        {
            bool isService = args.Contains("-service");
            if (isService)
            {
                var pathToExe = Process.GetCurrentProcess().MainModule.FileName;
                var pathToContentRoot = Path.GetDirectoryName(pathToExe);
                Directory.SetCurrentDirectory(pathToContentRoot);
            }

            var webHost = CreateWebHostBuilder(isService).Build();
            var logger = webHost.Services.GetRequiredService<ILogger<Program>>();
            var forwarder = webHost.Services.GetRequiredService<HttpForwarder>();
            ConfigureProcessPrivileges(logger);
            ActivateAssemblies(logger, forwarder);

            if (isService)
            {
                webHost.RunAsService();
            }
            else
            {
                webHost.Run();
            }
        }

        private static IWebHostBuilder CreateWebHostBuilder(bool service)
        {
            var config = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: true)
                .Build();

            return WebHost.CreateDefaultBuilder()
                .UseConfigurationSection(config.GetSection("Host"))
                .ConfigureLogging(logging =>
                {
                    logging.ClearProviders();
                    if (service)
                    {
                        logging.AddProvider(new DeferringLoggerProvider(new EventLogLoggerProvider()));
                    }
                    else
                    {
                        logging.AddConsole();
                    }
                })
                .UseStartup<Startup>()
#if NETFX
                .UseSetting(WebHostDefaults.HostingStartupAssembliesKey, "Microsoft.AspNetCore.WebUtilities")
#endif
            ;
        }

        private static void ConfigureProcessPrivileges(ILogger logger)
        {
            var process = Process.GetCurrentProcess();
            var tcbState = process.GetPrivilegeState(Privilege.TrustedComputerBase);

#if NETFX
            if (tcbState != PrivilegeState.Removed)
            {
                logger.LogWarning("Process is assigned excessive privileges. TrustedComputerBase is not required.");
            }
#elif COREFX
            if (tcbState == PrivilegeState.Removed)
            {
                logger.LogCritical("TrustedComputerBase privilege is required, but not assigned to the process.");
                throw new SystemException("Required Privilege not held");
            }
            else if (tcbState == PrivilegeState.Disabled)
            {
                logger.LogInformation("TrustedComputerBase privilege ");
                try
                {
                    process.EnablePrivilege(Privilege.TrustedComputerBase);
                    logger.LogInformation("Successfully enabled the TrustedComputerBase privilege.");
                }
                catch (Exception e)
                {
                    logger.LogCritical(e, "Failed to enable the TrustedComputerBase privilege.");
                    throw e;
                }
            }
            else
            {
                logger.LogInformation("TrustedComputerBase privilege is enabled.");
            }
#endif
        }

        private static void ActivateAssemblies(ILogger logger, HttpForwarder forwarder)
        {
            logger.LogInformation("Starting assembly primer request.");
            // Prime assembly loads to avoid impersonation crash. Simply preloading the assemblies is not sufficient.
            try
            {
                var request = new HttpRequestMessage(HttpMethod.Get, "http://invalid/");
                var result = forwarder.ForwardAsync(request, new System.Threading.CancellationToken());
                result.Wait();
            }
            catch (Exception)
            {
            }
            logger.LogInformation("Finished assembly primer request.");
        }
    }

    // Temporary until ASP.Net Core 3.0
    public static class WebHostConfigurationSection
    {
        /// <summary>
        /// Use the given configuration settings on the web host. Compatible with the configuration section.
        /// </summary>
        /// <param name="hostBuilder">The <see cref="IWebHostBuilder"/> to configure.</param>
        /// <param name="configuration">The <see cref="IConfiguration"/> containing settings to be used.</param>
        /// <returns>The <see cref="IWebHostBuilder"/>.</returns>
        public static IWebHostBuilder UseConfigurationSection(this IWebHostBuilder hostBuilder, IConfiguration configuration)
        {
            foreach (var setting in configuration.AsEnumerable(makePathsRelative: true))
            {
                hostBuilder.UseSetting(setting.Key, setting.Value);
            }

            return hostBuilder;
        }
    }
}
