using System;
using System.Buffers;

namespace Crypto.Utils
{
    public class Crc32
    {
        public static readonly ReadOnlyMemory<uint> Table;

        static Crc32()
        {
            var table = new uint[256];

            for (var b = 0u; b < 256; b++)
            {
                // Start with the data byte
                var remainder = b;
                for (var bit = 8u; bit > 0; --bit)
                {
                    if ((remainder & 1) != 0)
                        remainder = (remainder >> 1) ^ 0xedb88320u;
                    else
                        remainder = (remainder >> 1);
                }
                table[b] = remainder;

            }

            Table = table;
        }

        public static uint Checksum(ReadOnlyMemory<byte> input)
        {
            return InnerChecksum(input, 0xffffffffu) ^ 0xffffffffu;
        }

        public static uint Checksum(ReadOnlySequence<byte> input)
        {
            var checksum = 0xffffffffu;
            if (input.IsSingleSegment) return InnerChecksum(input.First, checksum) ^ 0xffffffffu;

            foreach (var memory in input)
            {
                checksum = InnerChecksum(memory, checksum);
            }

            return checksum ^ 0xffffffffu;
        }

        private static uint InnerChecksum(ReadOnlyMemory<byte> input, uint checksum)
        {
            foreach (var b in input.Span)
            {
                var index = (byte)(checksum ^ b);
                checksum = (checksum >> 8) ^ Table.Span[index];
            }

            return checksum;
        }

    }
}
