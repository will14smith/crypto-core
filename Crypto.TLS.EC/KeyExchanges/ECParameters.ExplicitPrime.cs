using Crypto.EC.Maths;
using Crypto.Utils.IO;

namespace Crypto.TLS.EC.KeyExchanges
{
    public abstract partial class ECParameters
    {
        public class ExplicitPrime : ECParameters
        {
            public ExplicitPrime(FieldValue primeP, ECCurve curve, Point @base, FieldValue order, FieldValue cofactor)
            {
                PrimeP = primeP;
                Curve = curve;
                Base = @base;
                Order = order;
                Cofactor = cofactor;
            }

            public override ECCurveType CurveType { get; } = ECCurveType.ExplicitPrime;
            
            public FieldValue PrimeP { get; }
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