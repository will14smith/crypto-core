using System.Numerics;
using Crypto.ASN1;
using Crypto.Certificates.Keys;
using Crypto.Utils;

namespace Crypto.RSA.Keys
{
    public class RSAPrivateKey : PrivateKey
    {
        public RSAPrivateKey(ASN1Object asn1Key)
        {
            // NOTE: currently only supporting PKCS#1 without optional OtherPrimeInfos

            var keySeq = asn1Key as ASN1Sequence;
            SecurityAssert.NotNull(keySeq);
            SecurityAssert.Assert(keySeq.Count == 9);

            Modulus = GetInteger(keySeq, 1);
            var publicExponent = GetInteger(keySeq, 2);
            Exponent = GetInteger(keySeq, 3);
            var prime1 = GetInteger(keySeq, 4);
            var prime2 = GetInteger(keySeq, 5);
            var exponent1 = GetInteger(keySeq, 6);
            var exponent2 = GetInteger(keySeq, 7);
            // TODO var coefficent = GetInteger(keySeq, 8);

            SecurityAssert.Assert(Modulus == prime1 * prime2);
            SecurityAssert.Assert(exponent1 == Exponent % (prime1 - 1));
            SecurityAssert.Assert(exponent2 == Exponent % (prime2 - 1));
            // TODO assert Coefficent == ((inverse of q) mod p)

            PublicKey = new RSAPublicKey(Modulus, publicExponent);
        }

        public override PublicKey PublicKey { get; }

        public BigInteger Modulus { get; }
        public BigInteger Exponent { get; }

        protected override int HashCode => HashCodeHelper.ToInt(Modulus ^ Exponent);

        private BigInteger GetInteger(ASN1Sequence obj, int index)
        {
            SecurityAssert.Assert(index >= 0 && index < obj.Elements.Count);

            var elem = obj.Elements[index];
            var intElem = elem as ASN1Integer;
            SecurityAssert.NotNull(intElem);

            return intElem.Value;
        }

        protected override bool Equal(PrivateKey key)
        {
            var other = key as RSAPrivateKey;
            if (other == null) return false;

            return Modulus == other.Modulus
                   && Exponent == other.Exponent
                && Equals(PublicKey, other.PublicKey);
        }
    }
}