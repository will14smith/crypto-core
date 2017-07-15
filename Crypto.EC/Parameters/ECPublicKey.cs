using System;
using Crypto.Certificates.Keys;
using Crypto.EC.Maths;
using Crypto.EC.Maths.Prime;

namespace Crypto.EC.Parameters
{
    public class ECPublicKey : PublicKey
    {
        public Point<PrimeValue> Point { get; }

        public ECPublicKey(Point<PrimeValue> point)
        {
            Point = point;
        }

        protected override int HashCode => Point.GetHashCode();
        protected override bool Equal(PublicKey key)
        {
            var other = key as ECPublicKey;
            if (ReferenceEquals(other, null)) return false;
            
            return other.Point == Point;
        }

        public override byte[] GetBytes()
        {
            throw new NotImplementedException();
        }
    }
}