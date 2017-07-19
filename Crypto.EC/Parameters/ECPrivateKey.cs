using Crypto.Certificates.Keys;
using Crypto.EC.Maths;
using Crypto.Utils;

namespace Crypto.EC.Parameters
{
    public class ECPrivateKey : PrivateKey
    {
        public ECPrivateKey(ECPublicKey pub, FieldValue d)
        {
            ECPublicKey = pub;
            D = d;
        }

        public FieldValue D { get; }

        public ECPublicKey ECPublicKey { get; }
        public override PublicKey PublicKey => ECPublicKey;

        protected override bool Equal(PrivateKey key)
        {
            var other = key as ECPrivateKey;
            if (other == null) return false;

            return D == other.D && PublicKey.Equals(other.PublicKey);
        }

        protected override int HashCode => HashCodeHelper.ToInt(D.Value) ^ PublicKey.GetHashCode();
    }
}