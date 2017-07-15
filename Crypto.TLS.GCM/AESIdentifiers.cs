using System;
using Crypto.TLS.Identifiers;

namespace Crypto.TLS.GCM
{
    public static class GCMIdentifiers
    {
        public static readonly TLSCipherAlgorithm AES128_GCM = new TLSCipherAlgorithm(Guid.NewGuid());
        public static readonly TLSCipherAlgorithm AES256_GCM = new TLSCipherAlgorithm(Guid.NewGuid());
    }
}
