using System;
using System.Linq;
using System.Text;

namespace Crypto.Utils
{
    public static class HexConverter
    {
        public static byte[] FromHex(string s)
        {
            SecurityAssert.Assert(s.Length % 2 == 0);
            
            var buffer = new byte[s.Length / 2];

            for (var i = 0; i < buffer.Length; i++)
            {
                buffer[i] = (byte)(FromHex(s[2 * i]) << 4 | FromHex(s[2 * i + 1]));
            }

            return buffer;
        }

        public static byte FromHex(char c)
        {
            if (c >= '0' && c <= '9')
            {
                return (byte)(c - '0');
            }
            if (c >= 'a' && c <= 'f')
            {
                return (byte)(c - 'a' + 10);
            }
            if (c >= 'A' && c <= 'F')
            {
                return (byte)(c - 'A' + 10);
            }

            throw new ArgumentOutOfRangeException(nameof(c));
        }

        public static string ToHex(ReadOnlySpan<byte> buffer)
        {
            var sb = new StringBuilder();

            foreach (var x in buffer)
            {
                sb.Append(ToHexNibble((byte)(x >> 4)));
                sb.Append(ToHexNibble((byte)(x & 0xf)));
            }

            return sb.ToString();
        }
        public static char ToHexNibble(byte nibble)
        {
            if (nibble < 10)
            {
                return (char)(nibble + '0');
            }
            return (char)(nibble - 10 + 'a');
        }
    }
}
