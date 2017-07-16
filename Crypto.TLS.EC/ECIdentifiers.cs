using System;
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
    }
}
