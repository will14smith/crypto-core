using System;

namespace Crypto.TLS.Config
{
    public class AEADCipherConfig
    {
        public ReadOnlyMemory<byte> ClientIV { get; set; }
        public ReadOnlyMemory<byte> ServerIV { get; set; }
    }
}
