using System;
using Crypto.Core.Encryption;
using Crypto.Core.Randomness;
using Crypto.Utils;

namespace Crypto.RSA.Encryption
{
    public class RSACipher : RSACipherBase, ICipher
    {
        private readonly IRandom _random;

        public RSACipher(IRandom random)
        {
            _random = random;
        }

        public int KeySize
        {
            get
            {
                if (PublicKey != null) return PublicKey.Modulus.GetByteLength();
                if (PrivateKey != null) return PrivateKey.Modulus.GetByteLength();
                
                throw new InvalidOperationException();
            }
        }

        public void Encrypt(byte[] input, int inputOffset, byte[] output, int outputOffset, int length)
        {
            SecurityAssert.AssertBuffer(input, inputOffset, length);
            SecurityAssert.NotNull(PublicKey);

            var k = PublicKey.Modulus.GetByteLength();
            SecurityAssert.Assert(length <= k - 11);

            var ps = _random.RandomNonZeroBytes(k - length - 3);
            SecurityAssert.Assert(ps.Length >= 8);

            var em = new byte[k];
            em[0] = 0;
            em[1] = 2;
            Array.Copy(ps, 0, em, 2, ps.Length);
            em[ps.Length + 2] = 0;
            Array.Copy(input, inputOffset, em, ps.Length + 3, length);

            var m = OS2IP(em, 0, em.Length);
            var c = EncryptPrimative(m, PublicKey);

            var result = I2OSP(c, k);
            SecurityAssert.AssertBuffer(output, outputOffset, result.Length);
            Array.Copy(result, 0, output, outputOffset, result.Length);
        }

        public void Decrypt(byte[] input, int inputOffset, byte[] output, int outputOffset, int length)
        {
            SecurityAssert.AssertBuffer(input, inputOffset, length);
            SecurityAssert.NotNull(PrivateKey);

            var k = PrivateKey.Modulus.GetByteLength();
            SecurityAssert.Assert(k >= 11);
            SecurityAssert.Assert(length == k);

            var c = OS2IP(input, inputOffset, length);
            var m = DecryptPrimative(c, PrivateKey);

            var em = I2OSP(m, k);

            SecurityAssert.Assert(em[0] == 0 && em[1] == 2);

            var mIdx = 2;
            while (mIdx < k && em[mIdx] != 0) { mIdx++; }

            SecurityAssert.Assert(mIdx - 2 > 8);
            // advance past zero
            mIdx++;

            SecurityAssert.AssertBuffer(output, outputOffset, k - mIdx);
            Array.Copy(em, mIdx, output, outputOffset, k - mIdx);
        }
    }
}