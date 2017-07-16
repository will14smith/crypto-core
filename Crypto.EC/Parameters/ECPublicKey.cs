using System;
using Crypto.Certificates.Keys;
using Crypto.EC.Maths;
using Crypto.EC.Maths.Prime;

namespace Crypto.EC.Parameters
{
    public class ECPublicKey : PublicKey
    {
        public PrimeDomainParameters Parameters { get; }
        public Point<PrimeValue> Point { get; }

        public ECPublicKey(PrimeDomainParameters parameters, Point<PrimeValue> point)
        {
            Parameters = parameters;
            Point = point;
        }

        protected override bool Equal(PublicKey key)
        {
            var other = key as ECPublicKey;
            if (other == null) return false;

            return Parameters.Equals(other.Parameters)
                   && Point.Equals(other.Point);
        }

        public override byte[] GetBytes()
        {
            return Point.ToBytes();
        }

        protected override int HashCode => Parameters.GetHashCode() ^ Point.GetHashCode();
    }
}