using Crypto.EC.Maths;
using Crypto.EC.Maths.Prime;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.TLS.EC
{
    public static class EndianBinaryWriterExtensions
    {
        public static void Write(this EndianBinaryWriter writer, Point<PrimeValue> point)
        {
            // TODO respect ECPointFormatsConfig
            
            var x = point.X.ToInt().ToByteArray(Endianness.BigEndian);
            var y = point.Y.ToInt().ToByteArray(Endianness.BigEndian);
            SecurityAssert.Assert(x.Length == y.Length);
            
            // length
            writer.Write((byte)(1 + x.Length + y.Length));
            
            // type = uncompressed (4)
            writer.Write((byte)0x4);
            
            writer.Write(x);
            writer.Write(y);
        }
    }
}