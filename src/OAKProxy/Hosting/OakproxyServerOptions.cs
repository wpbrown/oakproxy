using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OAKProxy.Authenticator.Bearer;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using LogLevelEnum = Microsoft.Extensions.Logging.LogLevel;

namespace OAKProxy.Hosting
{
    public class OakproxyServerOptions
    {
        public bool UseForwardedHeaders { get; set; }

        [EnumDataType(typeof(LogLevel))]
        public string LogLevel { get; set; }

        public string ApplicationInsightsKey { get; set; }

        [Required]
        public string Urls { get; set; }

        public bool EnableHealthChecks { get; set; }

        public KeyManagement KeyManagement { get; set; }

        internal LogLevelEnum LogLevelInternal
        {
            get => Enum.TryParse(LogLevel, out LogLevelEnum result) ? result : LogLevelEnum.Information;
        }
    }

    public class KeyManagement : IValidatableObject
    {
        public string StoreToFilePath { get; set; }

        public string StoreToBlobContainer { get; set; }

        public string ProtectWithKeyVaultKey { get; set; }

        public X509Certificate2 ProtectWithCertificate { get; private set; }

        public X509Certificate2[] UnprotectWithCertificates { get; private set; }

        public DpapiNgOptions ProtectWithDpapiNg { get; set; }

        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
            yield break;
        }

        internal void LoadCertificates(IConfiguration configuration)
        {
            var protectSection = configuration.GetSection("ProtectWithCertificate");
            if (protectSection.Exists())
            {
                ProtectWithCertificate = KeyVaultOptions.LoadCertificateFromConfig(protectSection);
            }

            var unprotectSection = configuration.GetSection("UnprotectWithCertificates");
            if (unprotectSection.Exists())
            {
                var certSections = unprotectSection.GetChildren();
                UnprotectWithCertificates = certSections.Select(s => KeyVaultOptions.LoadCertificateFromConfig(s)).ToArray();
            }
        }
    }

    public class DpapiNgOptions : IValidatableObject
    {
        public bool UseSelfRule { get; set; }

        public string DescriptorRule { get; set; }

        public Microsoft.AspNetCore.DataProtection.XmlEncryption.DpapiNGProtectionDescriptorFlags DescriptorFlags { get; set; }

        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
            if (UseSelfRule ^ String.IsNullOrEmpty(DescriptorRule))
            {
                yield return new ValidationResult($"Either '{nameof(UseSelfRule)}' or '{nameof(DescriptorRule)}' is required for DPAPI-NG.", new string[] { nameof(UseSelfRule), nameof(DescriptorRule) });
            }

            if (UseSelfRule && DescriptorFlags != Microsoft.AspNetCore.DataProtection.XmlEncryption.DpapiNGProtectionDescriptorFlags.None)
            {
                yield return new ValidationResult($"If '{nameof(DescriptorFlags)}' are used a '{nameof(DescriptorRule)}' must be provided.", new string[] { nameof(DescriptorFlags), nameof(DescriptorRule) });
            }
        }
    }

    public class KeyVaultOptions
    {
        public KeyVaultOptions(IConfiguration configuration)
        {
            configuration.Bind(this);

            var certificateSection = configuration.GetSection("Certificate");
            if (certificateSection.Exists())
            {
                Certificate = LoadCertificateFromConfig(certificateSection);
            }
        }

        public string VaultUri
        {
            get => Name.StartsWith("https", StringComparison.InvariantCultureIgnoreCase) ?
                Name : $"https://{Name}.vault.azure.net/";
        }

        public string Name { get; set; }

        public string ClientId { get; set; }

        public string ClientSecret { get; set; }

        public X509Certificate2 Certificate { get; private set; }

        public static X509Certificate2 LoadCertificateFromConfig(IConfiguration config)
        {
            if (config["Path"] != null)
            {
                var certificateOptions = config.Get<CertificateFileOptions>();
                return new X509Certificate2(certificateOptions.Path, certificateOptions.Password);
            }
            else if (config["Subject"] != null)
            {
                var certificateOptions = config.Get<CertificateStoreOptions>();
                return Microsoft.AspNetCore.Server.Kestrel.Https.Internal.CertificateLoader
                    .LoadFromStoreCert(certificateOptions.Subject,
                        certificateOptions.Store,
                        certificateOptions.Location,
                        certificateOptions.AllowInvalid);
            }

            throw new Exception("Invalid certificate config object.");
        }
    }

    public class CertificateFileOptions
    {
        public string Path { get; set; }

        public string Password { get; set; }
    }

    public class CertificateStoreOptions
    {
        public string Subject { get; set; }

        public string Store { get; set; }

        public StoreLocation Location { get; set; }

        public bool AllowInvalid { get; set; }
    }
}
