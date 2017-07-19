using Crypto.EC.Maths;

namespace Crypto.TLS.EC.KeyExchanges
{
    public class ECCurve
    {
        public ECCurve(FieldValue a, FieldValue b)
        {
            A = a;
            B = b;
        }

        public FieldValue A { get; }
        public FieldValue B { get; }
    }
}