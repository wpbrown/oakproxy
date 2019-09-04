using System;
using Microsoft.Extensions.Configuration;

namespace OAKProxy.Hosting
{
    public class HostingSubsystemConfiguration
    {
        public IConfigurationSection Kestrel { get; private set; }

        public IConfigurationSection ApplicationInsights { get; private set; }

        public IConfigurationSection ForwardedHeaders { get; private set; }

        public IConfigurationSection Host { get; private set; }

        public IConfigurationSection Logging { get; private set; }

        public static HostingSubsystemConfiguration Empty()
        {
            var empty = new ConfigurationRoot(new IConfigurationProvider[] { }).GetSection(String.Empty);
            return new HostingSubsystemConfiguration
            {
                Kestrel = empty,
                ApplicationInsights = empty,
                ForwardedHeaders = empty,
                Host = empty,
                Logging = empty
            };
        }
    }
}
