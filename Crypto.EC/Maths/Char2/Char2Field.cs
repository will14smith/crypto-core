using System.Collections;
using System.Linq;
using System.Numerics;
using Crypto.Utils;

namespace Crypto.EC.Maths.Char2
{
    public class Char2Field : IField<Char2Value>
    {
        private readonly int _m;
        //TODO f == 2^m + 2^k3 + 2^k2 + 2^k1 + 1
        private readonly int[] _ks;

        public Char2Field(int m, int k) : this(m, new[] { k }) { }
        public Char2Field(int m, int k1, int k2, int k3) : this(m, new[] { k1, k2, k3 }) { }
        public Char2Field(int m, int[] ks)
        {
            SecurityAssert.Assert(m > 0);
            SecurityAssert.Assert(ks.Length == 1 || ks.Length == 3);

            _m = m;
            _ks = ks;
        }

        public Char2Value Int(BigInteger i)
        {
            SecurityAssert.Assert(i.GetBitLength() <= _m);

            return new Char2Value(i);
        }

        public Char2Value Negate(Char2Value a)
        {
            return a;
        }

        public Char2Value Add(Char2Value a, Char2Value b)
        {
            return new Char2Value(a.Value ^ b.Value);
        }

        public Char2Value Sub(Char2Value a, Char2Value b)
        {
            return Add(a, Negate(b));
        }

        public Char2Value Multiply(Char2Value av, Char2Value bv)
        {
            var a = new BitArray(av.Value.ToByteArray());
            var b = bv.Value;

            var c = a[0] ? b : 0;

            var bitMask = (1 << _m) - 1;
            var highBitMask = 1 << _m;

            var r = _ks.Aggregate(BigInteger.One, (current, k) => current | BigInteger.One << k);

            for (var i = 1; i < _m; i++)
            {
                b = b << 1;
                if ((b & highBitMask) != 0)
                {
                    b &= bitMask;
                    b ^= r;
                }

                if (a[i])
                {
                    c ^= b;
                }
            }

            return new Char2Value(c);
        }

        public Char2Value Divide(Char2Value a, Char2Value b)
        {
            return Multiply(a, Invert(b));
        }

        private Char2Value Invert(Char2Value a)
        {
            SecurityAssert.Assert(a.Value != 0);

            var u = a.Value;
            var v = (BigInteger.One << _m) | _ks.Aggregate(BigInteger.One, (current, k) => current | BigInteger.One << k);

            var g1 = BigInteger.One;
            var g2 = BigInteger.Zero;

            while (u != 1)
            {
                var j = u.GetBitLength() - v.GetBitLength();
                if (j < 0)
                {
                    (u, v) = (v, u);
                    (g1, g2) = (g2, g1);
                    j = -j;
                }

                u ^= v << j;
                g1 ^= g2 << j;
            }

            return new Char2Value(g1);
        }
    }
}
