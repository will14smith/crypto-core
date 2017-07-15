using System.Numerics;
using Crypto.ASN1;
using Crypto.Certificates.Keys;
using Crypto.Utils;

namespace Crypto.TLS.DH.Keys
{
    public class DHPrivateKey : PrivateKey
    {
        public DHPrivateKey(PublicKey publicKey, ASN1Object input)
        {
            PublicKey = publicKey;

            var param = input as ASN1Integer;
            SecurityAssert.NotNull(param);

            X = param.Value;
        }

        public BigInteger X { get; }

        public override PublicKey PublicKey { get; }
        
        protected override bool Equal(PrivateKey key)
        {
            var other = key as DHPrivateKey;
            if (other == null) return false;

            return X == other.X && PublicKey.Equals(other.PublicKey);
        }

        protected override int HashCode => HashCodeHelper.ToInt(X) ^ PublicKey.GetHashCode();
    }
}