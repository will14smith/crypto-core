using System.Collections.Generic;
using System.Linq;
using Crypto.TLS.Records;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.TLS
{
    public static class EndianBinaryWriterExtensions
    {
        public static void Write(this EndianBinaryWriter writer, RecordType type)
        {
            writer.Write((byte)type);
        }
        public static void Write(this EndianBinaryWriter writer, TLSVersion version)
        {
            writer.Write(version.Major);
            writer.Write(version.Minor);
        }

        public static void Write(this EndianBinaryWriter writer, CipherSuite value)
        {
            writer.Write((ushort)value);
        }
        public static void Write(this EndianBinaryWriter writer, CompressionMethod value)
        {
            writer.Write((byte)value);
        }

        public static void WriteUInt24(this EndianBinaryWriter writer, uint value)
        {
            SecurityAssert.Assert(value <= 0xFFFFFF);

            var buffer = writer.BitConverter.GetBytes(value);
            writer.Write(buffer, 1, 3);
        }

        public static void WriteByteVariable<T>(this EndianBinaryWriter writer, byte lengthSize, IReadOnlyCollection<T> data)
        {
            writer.WriteByteVariable(lengthSize, data.Cast<byte>().ToList());
        }
        public static void WriteByteVariable(this EndianBinaryWriter writer, byte lengthSize, IReadOnlyCollection<byte> data)
        {
            writer.WriteLength(lengthSize, 1, data.Count);
            foreach (var item in data)
            {
                writer.Write(item);
            }
        }

        public static void WriteUInt16Variable<T>(this EndianBinaryWriter writer, byte lengthSize, IReadOnlyCollection<T> data)
        {
            writer.WriteUInt16Variable(lengthSize, data.Cast<ushort>().ToList());
        }
        public static void WriteUInt16Variable(this EndianBinaryWriter writer, byte lengthSize, IReadOnlyCollection<ushort> data)
        {
            writer.WriteLength(lengthSize, 2, data.Count);
            foreach (var item in data)
            {
                writer.Write(item);
            }
        }
        
        private static void WriteLength(this EndianBinaryWriter writer, byte lengthSize, byte elementSize, int count)
        {
            SecurityAssert.Assert(lengthSize > 0 && lengthSize <= 3);

            var length = elementSize * count;
            
            switch (lengthSize)
            {
                case 1:
                    SecurityAssert.Assert(length <= 0xff);
                    writer.Write((byte)length);
                    break;
                case 2:
                    SecurityAssert.Assert(length <= 0xffff);
                    writer.Write((ushort)length);
                    break;
                default:
                    SecurityAssert.Assert(length <= 0xffffff);
                    writer.WriteUInt24((uint)length);
                    break;
            }
        }
    }
}