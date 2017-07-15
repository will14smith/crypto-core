using System.Linq;
using Crypto.TLS.Records;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.TLS
{
    public static class EndianBinaryReaderExtensions
    {
        public static RecordType ReadRecordType(this EndianBinaryReader reader)
        {
            return (RecordType)reader.ReadByte();
        }
        public static TLSVersion ReadVersion(this EndianBinaryReader reader)
        {
            var major = reader.ReadByte();
            var minor = reader.ReadByte();

            return new TLSVersion(major, minor);
        }

        public static uint ReadUInt24(this EndianBinaryReader reader)
        {
            var buffer = new byte[4];
            reader.BaseStream.Read(buffer, 1, 3);
            buffer[0] = 0;
            return reader.BitConverter.ToUInt32(buffer, 0);
        }

        public static T[] ReadBytesVariable<T>(this EndianBinaryReader reader, byte lengthSize, ushort min, ushort max)
        {
            return ReadBytesVariable(reader, lengthSize, min, max).Select(x => (T)(object)x).ToArray();
        }
        public static byte[] ReadBytesVariable(this EndianBinaryReader reader, byte lengthSize, ushort min, ushort max)
        {
            var length = ReadLength(reader, lengthSize, 1, min, max);

            return reader.ReadBytes(length);
        }

        public static T[] ReadUInt16Variable<T>(this EndianBinaryReader reader, byte lengthSize, ushort min, ushort max)
        {
            return ReadUInt16Variable(reader, lengthSize, min, max).Select(x => (T)(object)x).ToArray();
        }
        public static ushort[] ReadUInt16Variable(this EndianBinaryReader reader, byte lengthSize, ushort min, ushort max)
        {
            var length = ReadLength(reader, lengthSize, 2, min, max);
            var buffer = reader.ReadBytes(length * 2);
            var output = new ushort[length];

            for (var i = 0; i < length; i++)
            {
                output[i] = reader.BitConverter.ToUInt16(buffer, i * 2);
            }

            return output;
        }

        private static ushort ReadLength(EndianBinaryReader reader, byte lengthSize, byte elemSize, ushort min, ushort max)
        {
            SecurityAssert.Assert(lengthSize == 1 || lengthSize == 2);

            var rawLength = lengthSize == 1 ? reader.ReadByte() : reader.ReadUInt16();
            SecurityAssert.Assert(rawLength % elemSize == 0);
            var length = (ushort)(rawLength / elemSize);

            SecurityAssert.Assert(length >= min && length <= max);
            return length;
        }
    }
}
