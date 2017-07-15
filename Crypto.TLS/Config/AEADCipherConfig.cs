namespace Crypto.TLS.Config
{
    public class AEADCipherConfig
    {
        public byte[] ClientIV { get; set; }
        public byte[] ServerIV { get; set; }
    }
}
