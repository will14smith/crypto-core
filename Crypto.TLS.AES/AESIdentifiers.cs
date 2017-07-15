using System;
using Crypto.TLS.Identifiers;

namespace Crypto.TLS.AES
{
    public static class AESIdentifiers
    {
        public static readonly TLSCipherAlgorithm AES128_CBC = new TLSCipherAlgorithm(Guid.NewGuid());
        public static readonly TLSCipherAlgorithm AES256_CBC = new TLSCipherAlgorithm(Guid.NewGuid());
    }
}
