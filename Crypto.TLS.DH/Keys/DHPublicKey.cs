using System;
using System.IO;
using System.Numerics;
using Crypto.ASN1;
using Crypto.Certificates.Keys;
using Crypto.TLS.DH.Config;
using Crypto.Utils;

namespace Crypto.TLS.DH.Keys
{
    public class DHPublicKey : PublicKey
    {
        public BigInteger P { get; }
        public BigInteger G { get; }
        public BigInteger Y { get; }

        public DHPublicKey(DHParameterConfig parameters, BigInteger y)
        {
            P = parameters.P;
            G = parameters.G;
            Y = y;
        }

        protected override bool Equal(PublicKey key)
        {
            var other = key as DHPublicKey;
            if (other == null) return false;

            return P == other.P
                   && G == other.G
                   && Y == other.Y;
        }

        public override ReadOnlySpan<byte> GetBytes()
        {
            var asn1 = new ASN1Integer(Y);

            using (var ms = new MemoryStream())
            {
                new DERWriter(ms).Write(asn1);

                return ms.ToArray();
            }
        }

        protected override int HashCode => HashCodeHelper.ToInt(P ^ G ^ Y);
    }
}