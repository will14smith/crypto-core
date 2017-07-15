using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using Crypto.Utils.IO;

namespace Crypto.Utils
{
    public static class BigIntegerExtensions
    {
        public static int GetByteLength(this BigInteger val)
        {
            var bytes = val.ToByteArray();
            var length = bytes.Length;

            while (length > 1 && bytes[length - 1] == 0)
            {
                length--;
            }

            return length;
        }
        public static int GetBitLength(this BigInteger val)
        {
            var length = 0;

            do
            {
                length++;
            } while ((val >>= 1) != 0);

            return length;
        }

        public static byte[] ToByteArray(this BigInteger val, Endianness endianness = Endianness.BigEndian)
        {
            var bytes = new List<byte>();

            while (val != 0)
            {
                bytes.Add((byte)(val % 256));

                val /= 256;
            }

            switch (endianness)
            {
                case Endianness.LittleEndian:
                    return bytes.ToArray();
                case Endianness.BigEndian:
                    return bytes.AsEnumerable().Reverse().ToArray();
                default:
                    throw new ArgumentOutOfRangeException(nameof(endianness), endianness, null);
            }
        }

        public static BigInteger HexToBigInteger(this string str, Endianness endianness = Endianness.BigEndian)
        {
            var arr = HexConverter.FromHex(str);
            return arr.ToBigInteger(endianness);
        }
        
        public static BigInteger ToBigInteger(this IEnumerable<byte> arr, Endianness endianness = Endianness.BigEndian)
        {
            switch (endianness)
            {
                case Endianness.LittleEndian:
                    var power = BigInteger.One;
                    var result = BigInteger.Zero;
                    foreach (var b in arr)
                    {
                        result = result + b * power;
                        power *= 256;
                    }
                    return result;
                case Endianness.BigEndian:
                    return arr.Aggregate(BigInteger.Zero, (current, b) => current * 256 + b);
                default:
                    throw new ArgumentOutOfRangeException(nameof(endianness), endianness, null);
            }
        }
    }
}
