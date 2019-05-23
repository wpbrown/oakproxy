using Microsoft.AspNetCore.Http;
using System;
using System.ComponentModel;
using System.Globalization;

namespace OAKProxy
{
    public class HostStringTypeConverter : TypeConverter
    {
        public override bool CanConvertFrom(ITypeDescriptorContext context, Type sourceType)
        {
            if (sourceType == null)
            {
                throw new ArgumentNullException(nameof(sourceType));
            }

            return sourceType == typeof(string) || sourceType == typeof(HostString);
        }

        public override bool CanConvertTo(ITypeDescriptorContext context, Type destinationType)
        {
            return destinationType == typeof(string) || destinationType == typeof(HostString);
        }

        public override object ConvertFrom(ITypeDescriptorContext context, CultureInfo culture, object value)
        {
            if (value is string hostString)
            {
                if (string.IsNullOrEmpty(hostString))
                {
                    return null;
                }

                return new HostString(hostString);
            }

            if (value is HostString host)
            {
                return new HostString(host.Value); 
            }

            throw GetConvertFromException(value);
        }

        public override object ConvertTo(ITypeDescriptorContext context, CultureInfo culture, object value, Type destinationType)
        {
            if (destinationType == null)
            {
                throw new ArgumentNullException(nameof(destinationType));
            }

            if (value is HostString host)
            {
                if (destinationType == typeof(string))
                {
                    return host.Value;
                }

                if (destinationType == typeof(HostString))
                {
                    return new HostString(host.Value);
                }
            }

            throw GetConvertToException(value, destinationType);
        }
    }
}