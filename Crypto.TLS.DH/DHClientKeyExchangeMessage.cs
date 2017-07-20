using System;
using System.Numerics;
using Crypto.TLS.Messages.Handshakes;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.TLS.DH
{
    public class DHClientKeyExchangeMessage : HandshakeMessage
    {
        public BigInteger Yc { get; }

        public DHClientKeyExchangeMessage(BigInteger yc)
            : base(HandshakeType.ClientKeyExchange)
        {
            Yc = yc;
        }

        protected override void Write(EndianBinaryWriter writer)
        {
            writer.WriteByteVariable(2, Yc.ToByteArray(Endianness.BigEndian));
        }

        public static DHClientKeyExchangeMessage Read(byte[] body)
        {
            var length = EndianBitConverter.Big.ToUInt16(body, 0);
            SecurityAssert.Assert(body.Length == length + 2);

            var param = new byte[length];
            Array.Copy(body, 2, param, 0, length);

            var yc = param.ToBigInteger(Endianness.BigEndian);

            return new DHClientKeyExchangeMessage(yc);
        }
    }
}
