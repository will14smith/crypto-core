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

        public void Encrypt(ReadOnlySpan<byte> input, Span<byte> output)
        {
            SecurityAssert.NotNull(PublicKey);

            var k = PublicKey.Modulus.GetByteLength();
            SecurityAssert.Assert(input.Length <= k - 11);

            var ps = _random.RandomNonZeroBytes(k - input.Length - 3);
            SecurityAssert.Assert(ps.Length >= 8);

            var em = new byte[k];
            em[0] = 0;
            em[1] = 2;
            Array.Copy(ps, 0, em, 2, ps.Length);
            em[ps.Length + 2] = 0;
            input.CopyTo(em.AsSpan(ps.Length + 3));

            var m = OS2IP(em);
            var c = EncryptPrimative(m, PublicKey);

            var result = I2OSP(c, k);
            SecurityAssert.Assert(output.Length >= result.Length);
            result.CopyTo(output);
        }

        public void Decrypt(ReadOnlySpan<byte> input, Span<byte> output)
        {
            SecurityAssert.NotNull(PrivateKey);

            var k = PrivateKey.Modulus.GetByteLength();
            SecurityAssert.Assert(k >= 11);
            SecurityAssert.Assert(input.Length == k);

            var c = OS2IP(input);
            var m = DecryptPrimative(c, PrivateKey);

            var em = I2OSP(m, k);

            SecurityAssert.Assert(em[0] == 0 && em[1] == 2);

            var mIdx = 2;
            while (mIdx < k && em[mIdx] != 0) { mIdx++; }

            SecurityAssert.Assert(mIdx - 2 > 8);
            // advance past zero
            mIdx++;

            SecurityAssert.Assert(output.Length >= k - mIdx);
            em.AsSpan(mIdx, k - mIdx).CopyTo(output);
        }
    }
}