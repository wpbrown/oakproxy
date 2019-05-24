﻿using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.WindowsServices;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.EventLog;
using OAKProxy.Logging;
using OAKProxy.Proxy;
using ProcessPrivileges;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace OAKProxy
{
    public class Program
    {
        public static void Main(string[] args)
        {
            TypeDescriptor.AddAttributes(typeof(HostString), new TypeConverterAttribute(typeof(HostStringTypeConverter)));

            bool isService = args.Contains("-service");
            bool useTcb = args.Contains("-tcb");
            if (isService)
            {
                var pathToExe = Process.GetCurrentProcess().MainModule.FileName;
                var pathToContentRoot = Path.GetDirectoryName(pathToExe);
                Directory.SetCurrentDirectory(pathToContentRoot);
            }

            var webHost = CreateWebHostBuilder(isService).Build();
            var logger = webHost.Services.GetRequiredService<ILogger<Program>>();
            var forwarder = webHost.Services.GetRequiredService<HttpForwarder>();
            ConfigureProcessPrivileges(logger, useTcb);

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
            // TODO clean up host config setup vs app config
            var hostConfig = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: true)
                .AddJsonFile("appsettings.Development.json", optional: true)
                .AddYamlFile("appsettings.yml", optional: true)
                .AddYamlFile("appsettings.Development.yml", optional: true)
                .Build();

            return new WebHostBuilder()
                .UseUrls(hostConfig.GetValue("Server:Urls", "http://*"))
                .UseContentRoot(Directory.GetCurrentDirectory())
                .UseConfigurationSection(hostConfig.GetSection("Configuration:Host"))
                .ConfigureAppConfiguration((hostingContext, config) =>
                {
                    var env = hostingContext.HostingEnvironment;

                    config.AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
                          .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true, reloadOnChange: true)
                          .AddYamlFile("appsettings.yml", optional: true, reloadOnChange: true)
                          .AddYamlFile($"appsettings.{env.EnvironmentName}.yml", optional: true, reloadOnChange: true);
                })
                .ConfigureLogging((hostingContext, logging) =>
                {
                    var loggingSection = hostingContext.Configuration.GetSection("Configuration:Logging");
                    if (loggingSection.Exists())
                    {
                        logging.AddConfiguration(loggingSection);
                    }
                    else
                    {
                        var level = hostingContext.Configuration.GetValue<LogLevel>("Server:LogLevel", LogLevel.Information);
                        logging.AddFilter(null, level);
                    }
                    
                    if (service)
                    {
                        logging.AddProvider(new DeferringLoggerProvider(new EventLogLoggerProvider(new EventLogSettings
                        {
                            SourceName = "OAKProxy"
                        })));
                    }
                    else
                    {
                        logging.AddConsole();
                    }
                })
                .UseDefaultServiceProvider((context, options) =>
                {
                    options.ValidateScopes = context.HostingEnvironment.IsDevelopment();
                })
                .UseKestrel((builderContext, options) =>
                {
                    options.Configure(builderContext.Configuration.GetSection("Configuration:Kestrel"));
                })
                .UseStartup<Startup>();
        }

        private static void ConfigureProcessPrivileges(ILogger logger, bool useTcb)
        {
            var process = Process.GetCurrentProcess();
            var tcbState = process.GetPrivilegeState(Privilege.TrustedComputerBase);

            if (tcbState != PrivilegeState.Removed)
            {
                logger.LogWarning("Process is assigned excessive privileges. TrustedComputerBase is not required.");
            }

            if (useTcb)
            {
                if (tcbState == PrivilegeState.Removed)
                {
                    logger.LogCritical("TrustedComputerBase privilege was requested, but not assigned to the process.");
                    throw new SystemException("Requested Privilege not held");
                }
                else if (tcbState == PrivilegeState.Disabled)
                {
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
                    logger.LogInformation("The requested TrustedComputerBase privilege is already enabled.");
                }
            }
            else
            {
                if (tcbState == PrivilegeState.Enabled)
                {
                    try
                    {
                        process.DisablePrivilege(Privilege.TrustedComputerBase);
                        logger.LogInformation("Successfully disabled the TrustedComputerBase privilege.");
                    }
                    catch (Exception e)
                    {
                        logger.LogCritical(e, "Failed to disable the TrustedComputerBase privilege.");
                        throw e;
                    }
                }
            }
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
