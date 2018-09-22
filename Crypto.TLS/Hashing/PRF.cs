using System;
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

        public IEnumerable<byte> Digest(ReadOnlyMemory<byte> secret, string label, ReadOnlySpan<byte> seed)
        {
            var labelBytes = Encoding.ASCII.GetBytes(label);

            var properSeed = new byte[labelBytes.Length + seed.Length].AsMemory();
            labelBytes.CopyTo(properSeed);
            seed.CopyTo(properSeed.Span.Slice(labelBytes.Length));

            return P_hash(secret, properSeed);
        }

        private IEnumerable<byte> P_hash(ReadOnlyMemory<byte> secret, ReadOnlyMemory<byte> seed)
        {
            var hmac = new HMAC(_digest, secret.Span);

            var a = seed;

            while (true)
            {
                hmac.Reset();
                hmac.Update(a.Span);
                a = hmac.Digest().ToArray();

                hmac.Reset();
                hmac.Update(a.Span);
                hmac.Update(seed.Span);

                var b = hmac.Digest().ToArray();
                for (var i = 0; i < b.Length; i++)
                {
                    yield return b[i];
                }
            }
        }
    }
}
