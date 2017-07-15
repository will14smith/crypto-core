using System;
using System.Collections;

namespace Crypto.Utils
{
    public static class BitArrayExtensions
    {
        public static byte GetByte(this BitArray arr, int offset)
        {
            SecurityAssert.NotNull(arr);

            var endPoint = Math.Min(arr.Length, offset + 8);

            byte value = 0;
            var shift = 0;
            for (var i = offset; i < endPoint; i++)
            {
                value |= (byte)((arr[i] ? 1 : 0) << shift++);
            }

            return value;
        }

        public static byte[] GetBytes(this BitArray arr, int bitOffset, int byteLength)
        {
            SecurityAssert.NotNull(arr);
            SecurityAssert.Assert(bitOffset < arr.Length);
            SecurityAssert.Assert(bitOffset + byteLength * 8 < arr.Length + 7);

            var buffer = new byte[byteLength];

            for (var i = 0; i < byteLength; i++)
            {
                buffer[i] = arr.GetByte(bitOffset + i * 8);
            }

            return buffer;
        }

        public static byte[] ToArray(this BitArray arr)
        {
            SecurityAssert.NotNull(arr);
            var dataLength = (int)Math.Ceiling(arr.Length / 8m);

            return arr.GetBytes(0, dataLength);
        }
    }
}
