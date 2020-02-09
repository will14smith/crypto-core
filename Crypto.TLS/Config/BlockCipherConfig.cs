namespace Crypto.TLS.Config
{
    public class BlockCipherConfig
    {
        public byte[]? ClientMACKey { get; set; }
        public byte[]? ServerMACKey { get; set; }
    }
}
