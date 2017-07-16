using Crypto.EC.Maths;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.TLS.EC.KeyExchanges
{
    public abstract partial class ECParameters
    {
        public class ExplicitChar2 : ECParameters
        {
            // TODO all these IFieldValue should be Char2Value
            public ExplicitChar2(ushort m, IFieldValue[] k, ECCurve curve, Point<IFieldValue> @base, IFieldValue order, IFieldValue cofactor)
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
            public IFieldValue[] K { get; }
            public ECCurve Curve { get; }
            public Point<IFieldValue> Base { get; }
            public IFieldValue Order { get; }
            public IFieldValue Cofactor { get; }

            public override void Write(EndianBinaryWriter writer)
            {
                throw new System.NotImplementedException();
            }
        }
    }
}