using System;
using Crypto.TLS.Identifiers;

namespace Crypto.TLS.RC4
{
    public static class RC4Identifiers
    {
        public static readonly TLSCipherAlgorithm RC4_128 = new TLSCipherAlgorithm(Guid.NewGuid());
    }
}
