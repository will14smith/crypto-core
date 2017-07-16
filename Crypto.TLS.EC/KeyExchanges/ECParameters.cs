using Crypto.Utils.IO;

namespace Crypto.TLS.EC.KeyExchanges
{
    public abstract partial class ECParameters
    {
        public abstract ECCurveType CurveType { get; }

        public virtual void Write(EndianBinaryWriter writer)
        {
            writer.Write((byte)CurveType);
        }
    }
}