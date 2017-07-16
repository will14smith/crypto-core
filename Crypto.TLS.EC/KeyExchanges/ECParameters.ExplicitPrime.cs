using Crypto.EC.Maths;
using Crypto.EC.Maths.Prime;
using Crypto.Utils.IO;

namespace Crypto.TLS.EC.KeyExchanges
{
    public abstract partial class ECParameters
    {
        public class ExplicitPrime : ECParameters
        {
            public ExplicitPrime(PrimeValue primeP, ECCurve curve, Point<PrimeValue> @base, PrimeValue order, PrimeValue cofactor)
            {
                PrimeP = primeP;
                Curve = curve;
                Base = @base;
                Order = order;
                Cofactor = cofactor;
            }

            public override ECCurveType CurveType { get; } = ECCurveType.ExplicitPrime;
            
            public PrimeValue PrimeP { get; }
            public ECCurve Curve { get; }
            public Point<PrimeValue> Base { get; }
            public PrimeValue Order { get; }
            public PrimeValue Cofactor { get; }

            public override void Write(EndianBinaryWriter writer)
            {
                throw new System.NotImplementedException();
            }
        }
    }
}