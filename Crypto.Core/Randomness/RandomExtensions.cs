using System;
using System.Numerics;
using Crypto.Utils;

namespace Crypto.Core.Randomness
{
    public static class RandomExtensions
    {
        public static byte[] RandomNonZeroBytes(this IRandom random, int length)
        {
            SecurityAssert.Assert(length >= 0);

            var bytes = new byte[length];

            for (var i = 0; i < length; i++)
            {
                bytes[i] = (byte)random.RandomInt(1, 255);
            }

            return bytes;
        }


        public static BigInteger RandomBig(this IRandom random, int bits)
        {
            SecurityAssert.Assert(bits > 0 && bits % 8 == 0);
            var value = random.RandomBytes(bits / 8).ToArray();

            // make sure it is positive
            if ((value[value.Length - 1] & 0x80) != 0)
            {
                Array.Resize(ref value, value.Length + 1);
            }

            return new BigInteger(value);
        }
        public static BigInteger RandomBig(this IRandom random, BigInteger max)
        {
            var bits = (int)Math.Ceiling(BigInteger.Log(max, 2) / 8) * 8;

            BigInteger val;
            do
            {
                val = random.RandomBig(bits);
            } while (val > max);

            return val;
        }
    }
}