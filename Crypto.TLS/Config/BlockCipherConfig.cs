using System;

namespace Crypto.TLS.Config
{
    public class BlockCipherConfig
    {
        public ReadOnlyMemory<byte> ClientMACKey { get; set; }
        public ReadOnlyMemory<byte> ServerMACKey { get; set; }
    }
}
