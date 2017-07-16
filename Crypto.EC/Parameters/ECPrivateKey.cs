using Crypto.Certificates.Keys;
using Crypto.EC.Maths.Prime;
using Crypto.Utils;

namespace Crypto.EC.Parameters
{
    public class ECPrivateKey : PrivateKey
    {
        public ECPrivateKey(ECPublicKey pub, PrimeValue d)
        {
            ECPublicKey = pub;
            D = d;
        }

        public PrimeValue D { get; }

        public ECPublicKey ECPublicKey { get; }
        public override PublicKey PublicKey => ECPublicKey;

        protected override bool Equal(PrivateKey key)
        {
            var other = key as ECPrivateKey;
            if (other == null) return false;

            return D == other.D && PublicKey.Equals(other.PublicKey);
        }

        protected override int HashCode => HashCodeHelper.ToInt(D.ToInt()) ^ PublicKey.GetHashCode();
    }
}