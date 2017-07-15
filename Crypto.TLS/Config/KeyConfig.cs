namespace Crypto.TLS.Config
{
    public class KeyConfig
    {
        public byte[] Master { get; set; }
        
        public byte[] Client { get; set; }
        public byte[] Server { get; set; }
    }
}
