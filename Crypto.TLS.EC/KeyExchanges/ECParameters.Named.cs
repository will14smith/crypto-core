using Crypto.TLS.EC.Services;
using Crypto.Utils.IO;

namespace Crypto.TLS.EC.KeyExchanges
{
    public abstract partial class ECParameters
    {
        public class Named : ECParameters
        {
            public Named(NamedCurve curve)
            {
                Curve = curve;
            }

            public override ECCurveType CurveType => ECCurveType.NamedCurve;

            public NamedCurve Curve { get; }

            public override void Write(EndianBinaryWriter writer)
            {
                base.Write(writer);
                
                writer.Write((ushort)Curve);
            }
        }
    }
}