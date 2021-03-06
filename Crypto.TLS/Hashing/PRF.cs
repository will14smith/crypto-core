﻿using System;
using System.Collections.Generic;
using System.Text;
using Crypto.Core.Hashing;

namespace Crypto.TLS.Hashing
{
    public class PRF
    {
        private readonly IDigest _digest;

        public PRF(IDigest digest)
        {
            _digest = digest;
        }

        public IEnumerable<byte> Digest(byte[] secret, string label, byte[] seed)
        {
            var labelBytes = Encoding.ASCII.GetBytes(label);

            var properSeed = new byte[labelBytes.Length + seed.Length];
            Array.Copy(labelBytes, 0, properSeed, 0, labelBytes.Length);
            Array.Copy(seed, 0, properSeed, labelBytes.Length, seed.Length);

            return P_hash(secret, properSeed);
        }

        private IEnumerable<byte> P_hash(byte[] secret, byte[] seed)
        {
            var hmac = new HMAC(_digest, secret);

            var a = seed;

            while (true)
            {
                hmac.Reset();
                hmac.Update(a);
                a = hmac.DigestBuffer();

                hmac.Reset();
                hmac.Update(a);
                hmac.Update(seed);

                var b = hmac.DigestBuffer();
                foreach (var x in b)
                {
                    yield return x;
                }
            }
        }
    }
}
