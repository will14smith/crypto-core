using Crypto.TLS.Identifiers;

namespace Crypto.TLS.SHA
{
    public static class SHAIdentifiers
    {
        public static readonly TLSHashAlgorithm SHA1 = new TLSHashAlgorithm(2);
        public static readonly TLSHashAlgorithm SHA256 = new TLSHashAlgorithm(4);
        public static readonly TLSHashAlgorithm SHA384 = new TLSHashAlgorithm(5);
    }
}
