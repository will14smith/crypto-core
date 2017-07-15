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

        public static void WriteVariable(this EndianBinaryWriter writer, byte lengthSize, byte[] value)
        {
            SecurityAssert.Assert(lengthSize > 0 && lengthSize <= 3);

            switch (lengthSize)
            {
                case 1:
                    SecurityAssert.Assert(value.Length <= 0xff);
                    writer.Write((byte)value.Length);
                    break;
                case 2:
                    SecurityAssert.Assert(value.Length <= 0xffff);
                    writer.Write((ushort)value.Length);
                    break;
                default:
                    SecurityAssert.Assert(value.Length <= 0xffffff);
                    writer.WriteUInt24((uint)value.Length);
                    break;
            }

            writer.Write(value);
        }

    }
}