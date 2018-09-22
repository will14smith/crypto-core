using System;
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
        public ReadOnlySpan<byte> Sign(ReadOnlySpan<byte> input, IDigest hash)
        {
            SecurityAssert.NotNull(hash);
            SecurityAssert.NotNull(PrivateKey);

            var k = PrivateKey.Modulus.GetByteLength();

            var em = EMSA_PKCS1_v1_5_Encode(input, k, hash);

            var m = OS2IP(em);
            var s = SignPrimative(m, PrivateKey);

            return I2OSP(s, k);
        }

        public bool Verify(ReadOnlySpan<byte> input, ReadOnlySpan<byte> signature, IDigest hash)
        {
            SecurityAssert.NotNull(hash);
            SecurityAssert.NotNull(PublicKey);

            var k = PublicKey.Modulus.GetByteLength();
            SecurityAssert.Assert(signature.Length == k);

            var s = OS2IP(signature);
            var m = VerifyPrimative(s, PublicKey);
            var em = I2OSP(m, k);

            var em2 = EMSA_PKCS1_v1_5_Encode(input, k, hash);

            if (em.Length != em2.Length)
            {
                return false;
            }

            return SpanExtensions.EqualConstantTime(em, em2);
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
