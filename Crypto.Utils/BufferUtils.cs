using System.Collections.Generic;

namespace Crypto.Utils
{
    public static class BufferUtils
    {
        public static void Xor(byte[] input, int inputOffset, byte[] target, int targetOffset, int length)
        {
            SecurityAssert.AssertBuffer(input, inputOffset, length);
            SecurityAssert.AssertBuffer(target, targetOffset, length);

            for (var i = 0; i < length; i++)
            {
                target[targetOffset + i] ^= input[inputOffset + i];
            }
        }

        public static bool EqualConstantTime(IReadOnlyList<byte> a, IReadOnlyList<byte> b)
        {
            if (ReferenceEquals(a, b))
            {
                return true;
            }
            if (ReferenceEquals(a, null) || ReferenceEquals(b, null))
            {
                return false;
            }

            if (a.Count != b.Count)
            {
                return false;
            }

            var result = 0;
            for (var i = 0; i < a.Count; i++)
            {
                result |= a[i] ^ b[i];
            }
            return result == 0;
        }
    }
}
