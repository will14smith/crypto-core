using Crypto.EC.Maths;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.TLS.EC.KeyExchanges
{
    public abstract partial class ECParameters
    {
        public class ExplicitChar2 : ECParameters
        {
            public ExplicitChar2(ushort m, int[] k, ECCurve curve, Point @base, FieldValue order, FieldValue cofactor)
            {
                SecurityAssert.Assert(k.Length == 1 || k.Length == 3);

                M = m;
                K = k;
                Curve = curve;
                Base = @base;
                Order = order;
                Cofactor = cofactor;
            }

            public override ECCurveType CurveType { get; } = ECCurveType.ExplicitChar2;

            public ushort M { get; }
            public ECBasisType Basis => K.Length == 1 ? ECBasisType.Trinomial : ECBasisType.Pentanomial;
            public int[] K { get; }
            public ECCurve Curve { get; }
            public Point Base { get; }
            public FieldValue Order { get; }
            public FieldValue Cofactor { get; }

            public override void Write(EndianBinaryWriter writer)
            {
                throw new System.NotImplementedException();
            }
        }
    }
}