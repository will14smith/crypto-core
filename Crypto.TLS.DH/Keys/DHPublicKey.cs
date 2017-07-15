using System.IO;
using System.Numerics;
using Crypto.ASN1;
using Crypto.Certificates.Keys;
using Crypto.Utils;

namespace Crypto.TLS.DH.Keys
{
    public class DHPublicKey : PublicKey
    {
        public BigInteger P { get; }
        public BigInteger G { get; }

        public DHPublicKey(BigInteger p, BigInteger g)
        {
            P = p;
            G = g;
        }

        protected override bool Equal(PublicKey key)
        {
            var other = key as DHPublicKey;
            if (other == null) return false;

            return P == other.P && G == other.G;
        }

        public override byte[] GetBytes()
        {
            var asn1 = new ASN1Sequence(new[]
            {
                new ASN1Integer(P),
                new ASN1Integer(G),
            });

            using (var ms = new MemoryStream())
            {
                new DERWriter(ms).Write(asn1);

                return ms.ToArray();
            }
        }

        protected override int HashCode => HashCodeHelper.ToInt(P ^ G);
    }
}