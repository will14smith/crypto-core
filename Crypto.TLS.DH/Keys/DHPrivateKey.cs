using System.Numerics;
using Crypto.ASN1;
using Crypto.Certificates.Keys;
using Crypto.TLS.DH.Config;
using Crypto.Utils;

namespace Crypto.TLS.DH.Keys
{
    public class DHPrivateKey : PrivateKey
    {
        public DHPrivateKey(DHParameterConfig parameters, ASN1Object input)
        {
            var param = input as ASN1Integer;
            SecurityAssert.NotNull(param);

            X = param.Value;
            
            var y = BigInteger.ModPow(parameters.G, X, parameters.P);
            
            DHPublicKey = new DHPublicKey(parameters, y);
        }

        public BigInteger X { get; }

        public DHPublicKey DHPublicKey { get; }
        public override PublicKey PublicKey => DHPublicKey;
        
        protected override bool Equal(PrivateKey key)
        {
            var other = key as DHPrivateKey;
            if (other == null) return false;

            return X == other.X && PublicKey.Equals(other.PublicKey);
        }

        protected override int HashCode => HashCodeHelper.ToInt(X) ^ PublicKey.GetHashCode();
    }
}