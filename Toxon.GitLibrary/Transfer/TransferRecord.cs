using System;
using System.Buffers;
using System.Text;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Toxon.GitLibrary.Transfer
{
    public class TransferRecord
    {
        public static readonly ReadOnlyMemory<byte> Flush = Encoding.UTF8.GetBytes("0000");

        public static (ReadOnlySequence<byte> Record, ReadOnlySequence<byte> RemainingInput) Read(ReadOnlySequence<byte> input)
        {
            if (input.Length < 4)
            {
                throw new Exception("invalid format");
            }

            var lengthStringBytes = input.Slice(0, 4);
            var lengthBytes = HexConverter.FromHex(lengthStringBytes).ToArray();
            var length = EndianBitConverter.Big.ToUInt16(lengthBytes);

            input = input.Slice(4);
            if (length == 0)
            {
                return (ReadOnlySequence<byte>.Empty, input);
            }

            if (length == 4 || length - 4 > input.Length)
            {
                throw new Exception("invalid format");
            }

            return input.Split((int)(length - 4));
        }

        public static ReadOnlySequence<byte> ReadFlush(ReadOnlySequence<byte> content)
        {
            var (flush, remaining) = content.Split(Flush.Length);

            if (!flush.StartsWith(Flush.Span))
            {
                throw new Exception("invalid format");
            }

            return remaining;
        }
    }
}