using System;
using System.Buffers;
using System.Linq;
using System.Text;

namespace Crypto.Utils
{
    public static class HexConverter
    {
        public static ReadOnlySpan<byte> FromHex(string s)
        {
            SecurityAssert.Assert(s.Length % 2 == 0);

            var buffer = new byte[s.Length / 2];

            for (var i = 0; i < buffer.Length; i++)
            {
                buffer[i] = (byte)(FromHex(s[2 * i]) << 4 | FromHex(s[2 * i + 1]));
            }

            return buffer;
        }

        public static ReadOnlySequence<byte> FromHex(ReadOnlySpan<byte> s)
        {
            SecurityAssert.Assert(s.Length % 2 == 0);

            var buffer = new byte[s.Length / 2];

            var i = 0;
            byte b = 0;
            foreach (var x in s)
            {
                if ((i & 1) == 0)
                {
                    b = FromHex((char)x);
                }
                else
                {
                    b = (byte)((b << 4) | FromHex((char)x));
                    buffer[i >> 1] = b;
                }

                i++;
            }

            return SequenceExtensions.Create<byte>(buffer);
        }

        public static ReadOnlySequence<byte> FromHex(ReadOnlySequence<byte> s)
        {
            SecurityAssert.Assert(s.Length % 2 == 0);

            var buffer = new byte[s.Length / 2];

            var i = 0;
            byte b = 0;
            foreach (var segment in s)
            {
                foreach (var x in segment.Span)
                {
                    if ((i & 1) == 0)
                    {
                        b = FromHex((char)x);
                    }
                    else
                    {
                        b = (byte)((b << 4) | FromHex((char)x));
                        buffer[i >> 1] = b;
                    }

                    i++;
                }
            }


            return SequenceExtensions.Create<byte>(buffer);
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

        public static string ToHex(ReadOnlySequence<byte> buffer)
        {
            var sb = new StringBuilder();

            foreach (var segment in buffer)
            {
                foreach (var x in segment.Span)
                {
                    sb.Append(ToHexNibble((byte)(x >> 4)));
                    sb.Append(ToHexNibble((byte)(x & 0xf)));
                }
            }

            return sb.ToString();
        }
        public static ReadOnlyMemory<byte> ToHexBytes(ReadOnlySequence<byte> buffer)
        {
            var result = new byte[buffer.Length << 1];

            var i = 0;
            foreach (var segment in buffer)
            {
                foreach (var x in segment.Span)
                {
                    result[i++] = (byte)ToHexNibble((byte)(x >> 4));
                    result[i++] = (byte)ToHexNibble((byte)(x & 0xf));
                }
            }

            return result;
        }

        public static string ToHex(ReadOnlySpan<byte> buffer)
        {
            var sb = new StringBuilder();

            for (var i = 0; i < buffer.Length; i++)
            {
                var x = buffer[i];

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
