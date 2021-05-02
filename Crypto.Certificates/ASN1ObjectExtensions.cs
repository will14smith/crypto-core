using System;
using Crypto.ASN1;

namespace Crypto.Certificates
{
    internal static class ASN1ObjectExtensions
    {
        public static string FromDirectoryString(this ASN1Object? asn1)
        {
            if (asn1 is ASN1UTF8String utf8)
            {
                return utf8.Value;
            }
            
            if (asn1 is ASN1PrintableString printable)
            {
                return printable.Value;
            }

            //TODO TeletexString
            //TODO PrintableString
            //TODO UniversalString
            //TODO BMPString

            throw new NotImplementedException();
        }

        public static string FromPrintableString(this ASN1Object? asn1)
        {
            throw new NotImplementedException();
        }

        public static DateTimeOffset GetTime(this ASN1Object? asn1)
        {
            if (asn1 is ASN1UTCTime utc)
            {
                return utc.Value;
            }

            //TODO GeneralizedTime

            throw new NotImplementedException();
        }
    }
}
