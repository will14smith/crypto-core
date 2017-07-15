using System;
using Crypto.TLS.Identifiers;

namespace Crypto.TLS.RSA
{
    public static class RSAIdentifiers
    {
        public static readonly TLSSignatureAlgorithm RSASig = new TLSSignatureAlgorithm(1);
        public static readonly TLSKeyExchange RSAKex = new TLSKeyExchange(Guid.NewGuid());
    }
}
