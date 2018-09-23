using System;
using Crypto.Certificates.Keys;
using Crypto.EC.Maths;

namespace Crypto.EC.Parameters
{
    public class ECPublicKey : PublicKey
    {
        public DomainParameters Parameters { get; }
        public Point Point { get; }

        public ECPublicKey(DomainParameters parameters, Point point)
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

        public override ReadOnlySpan<byte> GetBytes()
        {
            return Point.ToBytes();
        }

        protected override int HashCode => Parameters.GetHashCode() ^ Point.GetHashCode();
    }
}