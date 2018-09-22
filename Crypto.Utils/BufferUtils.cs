using System;

namespace Crypto.Utils
{
    public static class BufferUtils
    {
        public static void Xor(ReadOnlySpan<byte> input, Span<byte> output)
        {
            SecurityAssert.Assert(input.Length == output.Length);

            for (var i = 0; i < input.Length; i++)
            {
                output[i] ^= input[i];
            }
        }

        public static bool EqualConstantTime(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
        {
            if (a.Length != b.Length)
            {
                return false;
            }

            var result = 0;
            for (var i = 0; i < a.Length; i++)
            {
                result |= a[i] ^ b[i];
            }
            return result == 0;
        }
    }
}
