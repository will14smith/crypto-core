using Crypto.EC.Maths;

namespace Crypto.TLS.EC.KeyExchanges
{
    public class ECCurve
    {
        public ECCurve(IFieldValue a, IFieldValue b)
        {
            A = a;
            B = b;
        }

        // TODO these should be more specific types
        public IFieldValue A { get; }
        public IFieldValue B { get; }
    }
}