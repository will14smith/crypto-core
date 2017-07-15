using System;
using Crypto.ASN1;
using Crypto.TLS.Identifiers;

namespace Crypto.TLS.DH
{
    public static class DHIdentifiers
    {
        public static readonly TLSKeyExchange DHKex = new TLSKeyExchange(Guid.NewGuid());
        public static readonly TLSKeyExchange DHEKex = new TLSKeyExchange(Guid.NewGuid());

        public static readonly ASN1ObjectIdentifier DHKeyAgreement = new ASN1ObjectIdentifier("1.2.840.113549.1.3.1");

    }
}
