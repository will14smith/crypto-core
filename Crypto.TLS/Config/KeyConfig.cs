using System;

namespace Crypto.TLS.Config
{
    public class KeyConfig
    {
        public ReadOnlyMemory<byte> Master { get; set; }
        
        public ReadOnlyMemory<byte> Client { get; set; }
        public ReadOnlyMemory<byte> Server { get; set; }
    }
}
