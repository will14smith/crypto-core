using System;
using System.Numerics;
using Crypto.Utils;

namespace Crypto.EC.Maths.Prime
{
    public class PrimeField : IField<PrimeValue>
    {
        public BigInteger Prime { get; }

        public PrimeField(BigInteger prime)
        {
            Prime = prime;
        }

        public PrimeValue Int(BigInteger i)
        {
            i = i % Prime;
            if (i < 0)
            {
                i += Prime;
            }

            return new PrimeValue(i);
        }

        public PrimeValue Negate(PrimeValue a)
        {
            return Int(-a.Value);
        }

        public PrimeValue Add(PrimeValue a, PrimeValue b)
        {
            return Int(a.Value + b.Value);
        }

        public PrimeValue Sub(PrimeValue a, PrimeValue b)
        {
            return Int(a.Value - b.Value);
        }

        public PrimeValue Multiply(PrimeValue a, PrimeValue b)
        {
            return Int(a.Value * b.Value);
        }

        public PrimeValue Divide(PrimeValue a, PrimeValue b)
        {
            return Multiply(a, Invert(b));
        }

        private PrimeValue Invert(PrimeValue a)
        {
            var result = ExtendedEuclidean(a.Value, Prime);
            var gcd = result.Item1;
            var x = result.Item2;
            var y = result.Item3;

            SecurityAssert.Assert((a.Value * x + Prime * y) % Prime == gcd);

            if (gcd != 1)
            {
                // Either n is 0, or p is not a prime number.
                throw new Exception($"{a.Value} has no multiplicative inverse modulo {Prime}");
            }

            return Int(x);
        }

        private void DualAssign<T>(out T a, out T b, T aValue, T bValue)
        {
            a = aValue;
            b = bValue;
        }

        private Tuple<BigInteger, BigInteger, BigInteger> ExtendedEuclidean(BigInteger a, BigInteger b)
        {
            BigInteger s, oldS, t, oldT, r, oldR;

            DualAssign(out s, out oldS, 0, 1);
            DualAssign(out t, out oldT, 1, 0);
            DualAssign(out r, out oldR, b, a);

            while (r != 0)
            {
                var quotient = oldR / r;
                DualAssign(out oldR, out r, r, oldR - quotient * r);
                DualAssign(out oldS, out s, s, oldS - quotient * s);
                DualAssign(out oldT, out t, t, oldT - quotient * t);
            }

            return Tuple.Create(oldR, oldS, oldT);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            var other = obj as PrimeField;
            return other != null && Equals(other);
        }

        protected bool Equals(PrimeField other)
        {
            return Prime.Equals(other.Prime);
        }

        public override int GetHashCode()
        {
            return Prime.GetHashCode();
        }
    }
}