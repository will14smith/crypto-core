using System;
using Crypto.ASN1;
using Crypto.TLS.Extensions;
using Crypto.TLS.Identifiers;

namespace Crypto.TLS.EC
{
    public static class ECIdentifiers
    {
        public static readonly ExtensionType SupportedGroups = (ExtensionType) 10;
        public static readonly ExtensionType ECPointFormats = (ExtensionType) 11;

        public static readonly TLSSignatureAlgorithm ECDSA = new TLSSignatureAlgorithm(3);
        
        public static readonly TLSKeyExchange ECDHE = new TLSKeyExchange(Guid.NewGuid());

        public static readonly ASN1ObjectIdentifier ECPublickey = new ASN1ObjectIdentifier("1.2.840.10045.2.1");
        public static readonly ASN1ObjectIdentifier ECDSAWithSHA256 = new ASN1ObjectIdentifier("1.2.840.10045.4.3.2");
    }
}
