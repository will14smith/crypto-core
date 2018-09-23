using System;

namespace Crypto.TLS.Config
{
    public class RandomConfig
    {
        public ReadOnlyMemory<byte> Client { get; set; }
        public ReadOnlyMemory<byte> Server { get; set; }
    }
}
