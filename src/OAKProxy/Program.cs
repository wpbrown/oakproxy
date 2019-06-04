using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.WindowsServices;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.EventLog;
using Microsoft.Extensions.Options;
using OAKProxy.Logging;
using OAKProxy.Proxy;
using ProcessPrivileges;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;

namespace OAKProxy
{
    public class Program
    {
        public static void Main(string[] args)
        {
            TypeDescriptor.AddAttributes(typeof(HostString), new TypeConverterAttribute(typeof(HostStringTypeConverter)));
            var assembly = Assembly.GetEntryAssembly();
            var build = assembly.GetCustomAttribute<AssemblyFileVersionAttribute>().Version;
            var version = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>().InformationalVersion;
            var title = assembly.GetCustomAttribute<AssemblyTitleAttribute>().Title;
            var banner = $"Starting {title} version {version} build {build}.";

            bool isService = args.Contains("-service");
            bool useTcb = args.Contains("-tcb");
            if (isService)
            {
                Directory.SetCurrentDirectory(GetExecutableDirectory());
            }
            else
            {
                Console.WriteLine(banner);
            }

            var webHost = CreateWebHostBuilder(isService).Build();
            var logger = webHost.Services.GetRequiredService<ILogger<Program>>();
            logger.LogInformation(banner);

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
            var hostConfig = SetupConfiguration(new ConfigurationBuilder().SetBasePath(Directory.GetCurrentDirectory()))
                .Build();

            return new WebHostBuilder()
                .UseUrls(hostConfig.GetValue("Server:Urls", "http://*:9000"))
                .UseContentRoot(Directory.GetCurrentDirectory())
                .UseConfigurationSection(hostConfig.GetSection("Configuration:Host"))
                .ConfigureAppConfiguration((hostingContext, config) =>
                {
                    var env = hostingContext.HostingEnvironment;
                    SetupConfiguration(config, hostConfig, reload: true);
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
                .ConfigureServices((context, services) => {
                    services.AddOptions<ApplicationOptions>()
                        .Bind(context.Configuration)
                        .ValidateDataAnnotations();
                })
                .UseStartup<Startup>();
        }

        private static IConfigurationBuilder SetupConfiguration(IConfigurationBuilder builder, IConfiguration hostConfiguration = null, bool reload = false)
        {
            const string nameBase = "oakproxy";
            const string configFileExtension = "yml";
            const string configMapDirectoryName = "config";
            string configFileName = $"{nameBase}.{configFileExtension}";

            string configDirectory = Path.Combine(
                RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ?
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData, Environment.SpecialFolderOption.DoNotVerify) : 
                    "/etc",
                nameBase);

            // The central config file
            string configFile = Path.Combine(configDirectory, configFileName);
            if (File.Exists(configFile))
            {
                builder.AddYamlFile(configFile, optional: false, reloadOnChange: reload);
            }

            // The central config map directory
            string configMapDirectory = Path.Combine(configDirectory, configMapDirectoryName);
            if (Directory.Exists(configMapDirectory))
            {
                builder.AddKeyPerFile(configMapDirectory, optional: false);
            }

            // The local config file
            string localConfigFile = Path.Combine(GetExecutableDirectory(), configFileName);
            if (File.Exists(localConfigFile))
            {
                builder.AddYamlFile(localConfigFile, optional: false, reloadOnChange: reload);
            }

            // The current directory config file
            string workingConfigFile = Path.Combine(Directory.GetCurrentDirectory(), configFileName);
            if (File.Exists(workingConfigFile))
            {
                builder.AddYamlFile(workingConfigFile, optional: false, reloadOnChange: reload);
            }

            // Azure Key Vault
            var keyVaultSection = hostConfiguration?.GetSection("Server:KeyVault");
            if (keyVaultSection != null && keyVaultSection.Exists())
            {
                var options = new KeyVaultOptions(keyVaultSection);
                var vaultUri = options.Name.StartsWith("https", StringComparison.InvariantCultureIgnoreCase) ?
                    options.Name : $"https://{options.Name}.vault.azure.net/";

                if (options.ClientId == null)
                {
                    // Use Managed Identity
                    builder.AddAzureKeyVault(vaultUri);
                }
                else
                {
                    if (options.ClientSecret != null)
                    {
                        builder.AddAzureKeyVault(vaultUri, options.ClientId, options.ClientSecret);
                    }
                    else if (options.Certificate != null)
                    {
                        builder.AddAzureKeyVault(vaultUri, options.ClientId, options.Certificate);
                    }
                }
            }

            // Environment
            builder.AddEnvironmentVariables("O_");

            return builder;
        }

        private static string GetExecutableDirectory()
        {
            var pathToExe = Process.GetCurrentProcess().MainModule.FileName;
            return Path.GetDirectoryName(pathToExe);
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
