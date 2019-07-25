using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OAKProxy.Hosting;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace OAKProxy
{
    public class Program
    {
        static Program()
        {
            TypeDescriptor.AddAttributes(typeof(HostString), new TypeConverterAttribute(typeof(HostStringTypeConverter)));
        }

        public static async Task<int> Main(string[] arguments)
        {
            bool isWindows = IsWindows();
            bool isService = isWindows && arguments.Contains("-service");

            ILogger initLogger = GetEarlyInitializationLogger(useWindowsEventLog: isService);
            if (initLogger == null)
                return 1;

            string bannerData = AssembleBannerData();
            initLogger.LogInformation($"Initializing {bannerData}...");

            IConfiguration unifiedConfiguration = BuildUnifiedConfiguration();
            IHost host = OakproxyHostBuilder.Create(unifiedConfiguration, runAsWindowsService: isService, initLogger)?.Build();
            if (host == null)
                return 2;

            var logger = host.Services.GetRequiredService<ILogger<Program>>();
            logger.LogInformation($"Starting host for {bannerData}.");
            await host.RunAsync();
            logger.LogInformation($"Stopped host for {bannerData}.");

            return 0;
        }

        private static ILogger GetEarlyInitializationLogger(bool useWindowsEventLog)
        {
            string eventLogSource = useWindowsEventLog && EventLog.SourceExists("OAKProxy") ? "OAKProxy" : null;

            using var loggerFactory = LoggerFactory.Create(builder =>
            {
                if (useWindowsEventLog)
                {
                    builder.AddEventLog(configure => configure.SourceName = eventLogSource);
                }
                else
                {
                    builder.AddConsole();
                }
            });

            var logger = loggerFactory.CreateLogger("Initialization");
            if (useWindowsEventLog && eventLogSource == null)
            {
                logger.LogCritical("OAKProxy event log source is not registered. Aborting.");
                return null;
            }

            return logger;
        }

        private static string AssembleBannerData()
        {
            var assembly = Assembly.GetEntryAssembly();
            var build = assembly.GetCustomAttribute<AssemblyDescriptionAttribute>().Description;
            var version = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>().InformationalVersion;
            var title = assembly.GetCustomAttribute<AssemblyTitleAttribute>().Title;
            return $"{title} version {version} {build}.";
        }

        private static IConfiguration BuildUnifiedConfiguration()
        {
            var firstPassBuilder = new ConfigurationBuilder();
            AddConfigurationSourcesToBuilder(firstPassBuilder);
            var firstPassConfiguration = firstPassBuilder.Build();

            var keyVaultConfiguration = firstPassConfiguration.GetSection(ConfigurationPath.Combine("Server", "KeyVault"));
            var useKeyVaultForConfiguration = firstPassConfiguration.GetValue<bool>(ConfigurationPath.Combine("Server", "ConfigureFromKeyVault"));

            if (keyVaultConfiguration.Exists() && useKeyVaultForConfiguration)
            {
                var builder = new ConfigurationBuilder();
                AddConfigurationSourcesToBuilder(builder, keyVaultConfiguration);
                return builder.Build();
            }
            else
            {
                return firstPassConfiguration;
            }
        }

        private static void AddConfigurationSourcesToBuilder(IConfigurationBuilder builder, IConfigurationSection keyVaultConfiguration = null)
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
                builder.AddYamlFile(configFile, optional: false, reloadOnChange: true);
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
                builder.AddYamlFile(localConfigFile, optional: false, reloadOnChange: true);
            }

            // The current directory config file
            string workingConfigFile = Path.Combine(Directory.GetCurrentDirectory(), configFileName);
            if (File.Exists(workingConfigFile))
            {
                builder.AddYamlFile(workingConfigFile, optional: false, reloadOnChange: true);
            }

            // Azure Key Vault
            if (keyVaultConfiguration != null && keyVaultConfiguration.Exists())
            {
                var options = new KeyVaultOptions(keyVaultConfiguration);

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
        }

        private static bool IsWindows()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        }

        public static string GetExecutableDirectory()
        {
            var pathToExe = Process.GetCurrentProcess().MainModule.FileName;
            return Path.GetDirectoryName(pathToExe);
        }
    }
}
