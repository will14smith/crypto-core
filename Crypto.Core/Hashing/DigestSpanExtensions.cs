using System;
using Crypto.Utils;

namespace Crypto.Core.Hashing
{
    public static class DigestSpanExtensions
    {
        public static void Update(this IDigest digest, ReadOnlySpan<byte> input)
        {
            var buffer = input.ToArray();
            
            digest.Update(buffer, 0, buffer.Length);
        }

        public static void Digest(this IDigest digest, Span<byte> output)
        {
            SecurityAssert.AssertBuffer(output, digest.HashSize);
            
            var buffer = digest.Digest();
            buffer.CopyTo(output);
        }   
        public static byte[] DigestBuffer(this IDigest digest)
        {
            return digest.Digest();
        }
    }
}