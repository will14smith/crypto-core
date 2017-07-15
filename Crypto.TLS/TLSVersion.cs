namespace Crypto.TLS
{
    public struct TLSVersion
    {
        public static readonly TLSVersion TLS1_2 = new TLSVersion(3, 3);

        public byte Major { get; }
        public byte Minor { get; }

        public TLSVersion(byte major, byte minor)
        {
            Major = major;
            Minor = minor;
        }
    }
}
