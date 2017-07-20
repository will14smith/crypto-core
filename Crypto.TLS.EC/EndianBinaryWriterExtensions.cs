using Crypto.EC.Maths;
using Crypto.Utils.IO;

namespace Crypto.TLS.EC
{
    public static class EndianBinaryWriterExtensions
    {
        public static void Write(this EndianBinaryWriter writer, Point point)
        {
            // TODO respect ECPointFormatsConfig

            var b = point.ToBytes();
            writer.WriteByteVariable(1, b);
        }
    }
}