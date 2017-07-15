using Crypto.Utils;

namespace Crypto.TLS.Messages.Handshakes
{
    public class HelloExtension
    {
        public HelloExtension(ushort type, byte[] data)
        {
            Type = type;

            SecurityAssert.NotNull(data);
            SecurityAssert.Assert(data.Length >= 0 && data.Length <= 0xFFFF);
            Data = data;
        }

        public ushort Type { get; }
        public byte[] Data { get; }
    }
}
