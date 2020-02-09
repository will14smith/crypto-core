using System.Linq;
using System.Numerics;
using Crypto.Core.Hashing;
using Crypto.Core.Signing;
using Crypto.RSA.Keys;
using Crypto.Utils;

namespace Crypto.RSA.Encryption
{
    /// <summary>
    /// Currently only supports PKCS1-v1_5 scheme, OAEP & PSS are unsupported
    /// </summary>
    public class RSASignatureCipher : RSACipherBase, ISignatureCipher
    {
        public byte[] Sign(byte[] input, IDigest hash)
        {
            SecurityAssert.NotNull(input);
            SecurityAssert.NotNull(hash);
            SecurityAssert.NotNull(PrivateKey);

            var k = PrivateKey!.Modulus.GetByteLength();

            var em = EMSA_PKCS1_v1_5_Encode(input, k, hash);

            var m = OS2IP(em, 0, em.Length);
            var s = SignPrimative(m, PrivateKey!);

            return I2OSP(s, k);
        }

        public bool Verify(byte[] input, byte[] signature, IDigest hash)
        {
            SecurityAssert.NotNull(input);
            SecurityAssert.NotNull(signature);
            SecurityAssert.NotNull(hash);
            SecurityAssert.NotNull(PublicKey);

            var k = PublicKey!.Modulus.GetByteLength();
            SecurityAssert.Assert(signature.Length == k);

            var s = OS2IP(signature, 0, signature.Length);
            var m = VerifyPrimative(s, PublicKey!);
            var em = I2OSP(m, k);

            var em2 = EMSA_PKCS1_v1_5_Encode(input, k, hash);

            return em.Length == em2.Length && em.SequenceEqual(em2);
        }

        private static BigInteger SignPrimative(BigInteger m, RSAPrivateKey key)
        {
            return DecryptPrimative(m, key);
        }
        private static BigInteger VerifyPrimative(BigInteger m, RSAPublicKey key)
        {
            return EncryptPrimative(m, key);
        }
    }
}
