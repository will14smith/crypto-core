using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using Crypto.ASN1;
using Crypto.Core.Encryption.Parameters;
using Crypto.Core.Hashing;
using Crypto.RSA.Keys;
using Crypto.Utils;

namespace Crypto.RSA.Encryption
{
    public class RSACipherBase
    {
        internal RSAPublicKey PublicKey;
        internal RSAPrivateKey PrivateKey;

        public void Init(ICipherParameters parameters)
        {
            switch (parameters)
            {
                case RSAPublicKeyParameter pubKeyParams:
                    PublicKey = pubKeyParams.Key;
                    return;
                case RSAPrivateKeyParameter privKeyParams:
                    PrivateKey = privKeyParams.Key;
                    PublicKey = (RSAPublicKey)PrivateKey.PublicKey;
                    return;
                default:
                    throw new InvalidCastException();
            }

        }

        internal static BigInteger EncryptPrimative(BigInteger m, RSAPublicKey key)
        {
            SecurityAssert.Assert(m >= 0 && m < key.Modulus);

            return BigInteger.ModPow(m, key.Exponent, key.Modulus);
        }

        internal static BigInteger DecryptPrimative(BigInteger c, RSAPrivateKey key)
        {
            SecurityAssert.Assert(c >= 0 && c < key.Modulus);

            return BigInteger.ModPow(c, key.Exponent, key.Modulus);
        }

        internal static byte[] I2OSP(BigInteger x, int length)
        {
            SecurityAssert.Assert(x.Sign >= 0);
            SecurityAssert.Assert(x < BigInteger.Pow(256, length));

            var bytes = new List<byte>();

            while (x != 0)
            {
                bytes.Add((byte)(x % 256));

                x /= 256;
            }

            while (bytes.Count < length)
            {
                bytes.Add(0);
            }

            return bytes.AsEnumerable().Reverse().ToArray();
        }

        internal static BigInteger OS2IP(ReadOnlySpan<byte> x)
        {
            var result = BigInteger.Zero;
            foreach (var b in x) result = result * 256 + b;
            return result;
        }

        internal static ReadOnlySpan<byte> EMSA_PKCS1_v1_5_Encode(ReadOnlySpan<byte> input, int emLen, IDigest hash)
        {
            hash.Update(input);
            var h = hash.Digest();

            byte[] t;
            using (var mem = new MemoryStream())
            {
                var derWriter = new DERWriter(mem);

                derWriter.Write(new ASN1Sequence(new ASN1Object[]
                {
                    new ASN1Sequence(new ASN1Object[] {
                        hash.Id,
                        new ASN1Null()
                    }),
                    new ASN1OctetString(h.ToArray())
                }));

                t = mem.ToArray();
            }

            SecurityAssert.Assert(emLen >= t.Length + 11);

            var ps = new byte[emLen - t.Length - 3];
            SecurityAssert.Assert(ps.Length >= 8);
            for (var i = 0; i < ps.Length; i++) { ps[i] = 0xff; }

            var em = new byte[emLen];
            em[0] = 0;
            em[1] = 1;
            Array.Copy(ps, 0, em, 2, ps.Length);
            em[ps.Length + 2] = 0;
            Array.Copy(t, 0, em, ps.Length + 3, t.Length);

            return em;
        }
    }
}