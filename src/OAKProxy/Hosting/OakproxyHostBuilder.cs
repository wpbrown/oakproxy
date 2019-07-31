using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Azure.Storage.Auth;
using Microsoft.Azure.Storage.Blob;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.EventLog;
using Microsoft.Extensions.Options;
using OAKProxy.Extensions.Logging;
using OAKProxy.Proxy;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace OAKProxy.Hosting
{
    public static class OakproxyHostBuilder
    {
        public static IHostBuilder Create(IConfiguration configuration, bool runAsWindowsService, ILogger logger)
        {
            var builder = new HostBuilder();

            var serverOptions = new OakproxyServerOptions();
            serverOptions.Configure(configuration.GetSection("Server"));

            var proxyOptions = ConfigurationBinder.Get<ProxyOptions>(configuration);            
            if (!OptionsAreValid(serverOptions, logger, "Server") || !OptionsAreValid(proxyOptions, logger))
            {
                return null;
            }

            var subsystemConfiguration = ConfigurationBinder.Get<HostingSubsystemConfiguration>(configuration.GetSection("Configuration"),
                binderOptions => binderOptions.BindNonPublicProperties = true);

            builder
                .UseContentRoot(Program.GetExecutableDirectory())
                .ConfigureHostConfiguration(builder => builder.AddConfiguration(subsystemConfiguration.Host));

            if (runAsWindowsService)
            {
                builder.UseWindowsService();
            }

            builder
                .ConfigureAppConfiguration(builder => builder.AddConfiguration(configuration))
                .ConfigureLogging((hostBuilderContext, loggingBuilder) =>
                {
                    if (subsystemConfiguration.Logging.Exists())
                    {
                        loggingBuilder.AddConfiguration(subsystemConfiguration.Logging);
                    }
                    else
                    {
                        loggingBuilder.AddFilter(null, serverOptions.LogLevelInternal);
                    }

                    if (runAsWindowsService)
                    {
                        loggingBuilder.AddProvider(new DeferringLoggerProvider(new EventLogLoggerProvider(new EventLogSettings
                        {
                            SourceName = "OAKProxy"
                        })));
                    }
                    else
                    {
                        loggingBuilder.AddConsole();
                    }
                })
                .UseDefaultServiceProvider((context, options) =>
                {
                    options.ValidateScopes = context.HostingEnvironment.IsDevelopment();
                })
                .ConfigureServices((context, services) =>
                {
                    services.AddOptions<ProxyOptions>()
                        .Bind(configuration)
                        .ValidateDataAnnotations();

                    services.AddSingleton(Options.Create(serverOptions));

                    if (!String.IsNullOrWhiteSpace(serverOptions.ApplicationInsightsKey))
                    {
                        services.AddApplicationInsightsTelemetry(options =>
                        {
                            options.InstrumentationKey = serverOptions.ApplicationInsightsKey;
                            subsystemConfiguration.ApplicationInsights.Bind(options);
                        });
                        services.AddApplicationInsightsTelemetryProcessor<OakproxyTelemetryProcessor>();
                    }

                    services.AddTransient<IStartupFilter, HostingPipelineStartup>();

                    if (serverOptions.UseForwardedHeaders || serverOptions.UseAzureApplicationGateway)
                    {
                        services.Configure<ForwardedHeadersOptions>(options =>
                        {
                            options.ForwardedHeaders = ForwardedHeaders.All;
                            options.KnownNetworks.Clear();
                            options.KnownProxies.Clear();
                            subsystemConfiguration.ForwardedHeaders.Bind(options);

                            if (serverOptions.UseAzureApplicationGateway)
                            {
                                options.ForwardedHostHeaderName = "X-Original-Host";
                            }
                        });
                    }

                    if (serverOptions.KeyManagement != null)
                    {
                        var dataProtectionBuilder = services.AddDataProtection();
                        var kmOptions = serverOptions.KeyManagement;

                        kmOptions.LoadCertificates(configuration.GetSection(ConfigurationPath.Combine("Server", "KeyManagement")));

                        if (!String.IsNullOrEmpty(kmOptions.StoreToFilePath))
                        {
                            var directoryInfo = new DirectoryInfo(kmOptions.StoreToFilePath);
                            if (!directoryInfo.Exists)
                            {
                                throw new DirectoryNotFoundException("The specified key storage directory does not exist.");
                            }
                            dataProtectionBuilder.PersistKeysToFileSystem(directoryInfo);
                        }
                        else if (!String.IsNullOrEmpty(kmOptions.StoreToBlobContainer))
                        {
                            var blobUri = new Uri(kmOptions.StoreToBlobContainer);
                            if (String.IsNullOrEmpty(blobUri.Query))
                            {
                                var azureServiceTokenProvider = new AzureServiceTokenProvider();
                                var tokenAndFrequency = StorageTokenRenewerAsync(azureServiceTokenProvider, CancellationToken.None)
                                    .GetAwaiter().GetResult();

                                TokenCredential tokenCredential = new TokenCredential(tokenAndFrequency.Token,
                                                                                      StorageTokenRenewerAsync,
                                                                                      azureServiceTokenProvider,
                                                                                      tokenAndFrequency.Frequency.Value);

                                var storageCredentials = new StorageCredentials(tokenCredential);
                                var cloudBlockBlob = new CloudBlockBlob(blobUri, storageCredentials);
                                dataProtectionBuilder.PersistKeysToAzureBlobStorage(cloudBlockBlob);
                            }
                            else
                            {
                                dataProtectionBuilder.PersistKeysToAzureBlobStorage(blobUri);
                            }
                        }

                        if (!String.IsNullOrEmpty(kmOptions.ProtectWithKeyVaultKey))
                        {
                            var keyVaultSection = configuration.GetSection(ConfigurationPath.Combine("Server", "KeyVault"));
                            var kvOptions = new KeyVaultOptions(keyVaultSection);

                            var keyIdBuilder = new UriBuilder(kvOptions.VaultUri)
                            {
                                Path = $"/keys/${kmOptions.ProtectWithKeyVaultKey}"
                            };
                            var keyId = keyIdBuilder.Uri.ToString();

                            if (kvOptions.ClientId == null)
                            {
                                // Use Managed Identity
                                var azureServiceTokenProvider = new AzureServiceTokenProvider();
                                var authenticationCallback = new KeyVaultClient.AuthenticationCallback(azureServiceTokenProvider.KeyVaultTokenCallback);
                                dataProtectionBuilder.ProtectKeysWithAzureKeyVault(new KeyVaultClient(authenticationCallback), keyId);
                            }
                            else
                            {
                                if (kvOptions.ClientSecret != null)
                                {
                                    dataProtectionBuilder.ProtectKeysWithAzureKeyVault(keyId, kvOptions.ClientId, kvOptions.ClientSecret);
                                }
                                else if (kvOptions.Certificate != null)
                                {
                                    dataProtectionBuilder.ProtectKeysWithAzureKeyVault(keyId, kvOptions.ClientId, kvOptions.Certificate);
                                }
                            }
                        }
                        else if (kmOptions.ProtectWithCertificate != null)
                        {
                            dataProtectionBuilder.ProtectKeysWithCertificate(kmOptions.ProtectWithCertificate);

                            if (kmOptions.UnprotectWithCertificates != null)
                            {
                                dataProtectionBuilder.UnprotectKeysWithAnyCertificate(kmOptions.UnprotectWithCertificates);
                            }
                        }
                        else if (kmOptions.ProtectWithDpapiNg != null)
                        {
                            if (kmOptions.ProtectWithDpapiNg.UseSelfRule)
                            {
                                dataProtectionBuilder.ProtectKeysWithDpapiNG();
                            }
                            else
                            {
                                dataProtectionBuilder.ProtectKeysWithDpapiNG(kmOptions.ProtectWithDpapiNg.DescriptorRule, kmOptions.ProtectWithDpapiNg.DescriptorFlags);
                            }
                        }
                        else
                        {
                            throw new Exception("Unvalidated options would have allowed for unprotected key storage.");
                        }
                    }

                    services.AddHttpContextAccessor();
                    services.AddHealthChecks();
                    services.AddOakproxy(proxyOptions);
                })
                .ConfigureWebHost(configure =>
                {
                    configure.UseUrls(serverOptions.Urls);
                    configure.UseKestrel((builderContext, options) =>
                    {
                        options.Configure(subsystemConfiguration.Kestrel);

                        if (serverOptions.HttpsCertificate != null)
                        {
                            options.ConfigureHttpsDefaults(configureHttps => configureHttps.ServerCertificate = serverOptions.HttpsCertificate);
                        }
                    });
                    configure.Configure(builder => builder.UseOakproxy());
                });

            return builder;
        }

        private static bool OptionsAreValid(object options, ILogger logger, string memberNamePrefix = null)
        {
            var validationResults = new List<ValidationResult>();
            var context = new ValidationContext(options, serviceProvider: null, items: null);
            bool isValid = Validator.TryValidateObject(options, context, validationResults, validateAllProperties: true);
            foreach (var result in validationResults)
            {
                var memberNames = memberNamePrefix == null ? result.MemberNames :
                    result.MemberNames.Select(x => $"{memberNamePrefix}.{x}");
                logger.LogError($"{result.ErrorMessage}\nParameters: {String.Join(", ", memberNames)}");
            }
            return isValid;
        }

        private static async Task<NewTokenAndFrequency> StorageTokenRenewerAsync(object state, CancellationToken cancellationToken)
        {
            const string StorageResource = "https://storage.azure.com/";

            var authResult = await ((AzureServiceTokenProvider)state).GetAuthenticationResultAsync(StorageResource, null, cancellationToken);

            TimeSpan next = (authResult.ExpiresOn - DateTimeOffset.UtcNow) - TimeSpan.FromMinutes(5);
            if (next.Ticks < 0)
            {
                next = default;
            }

            return new NewTokenAndFrequency(authResult.AccessToken, next);
        }
    }
}
