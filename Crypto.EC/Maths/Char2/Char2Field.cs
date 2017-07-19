using System;
using System.Collections;
using System.Linq;
using System.Numerics;
using Crypto.Utils;

namespace Crypto.EC.Maths.Char2
{
    public class Char2Field : IField
    {
        private readonly int _m;
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

        public FieldValue Value(BigInteger i)
        {
            SecurityAssert.Assert(i.GetBitLength() <= _m, $"{i.GetBitLength()} <= {_m}");

            return new FieldValue(i);
        }

        public FieldValue Negate(FieldValue a)
        {
            return a;
        }

        public FieldValue Add(FieldValue a, FieldValue b)
        {
            return Value(a.Value ^ b.Value);
        }

        public FieldValue Sub(FieldValue a, FieldValue b)
        {
            return Add(a, Negate(b));
        }

        public FieldValue Multiply(FieldValue av, FieldValue bv)
        {
            var a = new BitArray(av.Value.ToByteArray());
            var b = bv.Value;

            var c = a[0] ? b : 0;

            var bitMask = (BigInteger.One << _m) - 1;
            var highBitMask = BigInteger.One << _m;

            var r = _ks.Aggregate(BigInteger.One, (current, k) => current | BigInteger.One << k);

            var max = Math.Min(_m, a.Count);
            for (var i = 1; i < max; i++)
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

            return Value(c);
        }

        public FieldValue Divide(FieldValue a, FieldValue b)
        {
            return Multiply(a, Invert(b));
        }

        private FieldValue Invert(FieldValue a)
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

            return Value(g1);
        }
    }
}
