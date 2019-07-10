using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.WindowsServices;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
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
            var build = assembly.GetCustomAttribute<AssemblyDescriptionAttribute>().Description;
            var version = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>().InformationalVersion;
            var title = assembly.GetCustomAttribute<AssemblyTitleAttribute>().Title;
            var banner = $"Starting {title} version {version} {build}.";

            bool isWindows = IsWindows();
            bool isService = isWindows && args.Contains("-service");
            
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

            if (isWindows)
            {
                bool useTcb = args.Contains("-tcb");
                ConfigureProcessPrivileges(logger, useTcb);
            }

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
                .UseConfiguration(hostConfig.GetSection("Configuration:Host"))
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

        private static bool IsWindows()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        }

        private static IConfigurationBuilder SetupConfiguration(IConfigurationBuilder builder, IConfiguration hostConfiguration = null, bool reload = false)
        {
            const string nameBase = "oakproxy";
            const string configFileExtension = "yml";
            const string configMapDirectoryName = "config";
            string configFileName = $"{nameBase}.{configFileExtension}";

            string configDirectory;
            if (IsWindows())
            {
                string baseConfigDirectory = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData, Environment.SpecialFolderOption.DoNotVerify);
                if (String.IsNullOrEmpty(baseConfigDirectory))
                    baseConfigDirectory = @"C:\";
                configDirectory = Path.Combine(baseConfigDirectory, nameBase);
            }
            else
            {
                configDirectory = "/etc";
            }

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
            var useKeyVaultConfiguration = hostConfiguration?.GetValue<bool>("Server:ConfigureFromKeyVault") ?? true;
            if (keyVaultSection != null && keyVaultSection.Exists() && useKeyVaultConfiguration)
            {
                var options = new KeyVaultOptions(keyVaultSection);

                if (options.ClientId == null)
                {
                    // Use Managed Identity
                    builder.AddAzureKeyVault(options.VaultUri);
                }
                else
                {
                    if (options.ClientSecret != null)
                    {
                        builder.AddAzureKeyVault(options.VaultUri, options.ClientId, options.ClientSecret);
                    }
                    else if (options.Certificate != null)
                    {
                        builder.AddAzureKeyVault(options.VaultUri, options.ClientId, options.Certificate);
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
}
