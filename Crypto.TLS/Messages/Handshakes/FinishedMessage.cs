using System;
using Crypto.TLS.Config;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.TLS.Messages.Handshakes
{
    public class FinishedMessage : HandshakeMessage
    {
        // TODO could in theory not be 12...
        public const int VerifyDataLength = 12; 
        
        public byte[] VerifyActual { get; }
        public byte[] VerifyExpectedHash { get; }

        public FinishedMessage(byte[] verifyActual, byte[] verifyExpectedHash) : base(HandshakeType.Finished)
        {
            SecurityAssert.NotNull(verifyActual);
            SecurityAssert.Assert(verifyActual.Length == VerifyDataLength);

            VerifyActual = verifyActual;
            VerifyExpectedHash = verifyExpectedHash;
        }

        protected override void Write(EndianBinaryWriter writer)
        {
            writer.Write(VerifyActual);
        }

        public static HandshakeMessage Read(byte[] body, byte[] currentHash)
        {
            var verifyData = new byte[VerifyDataLength];

            SecurityAssert.Assert(body.Length == VerifyDataLength);

            Array.Copy(body, verifyData, VerifyDataLength);

            return new FinishedMessage(verifyData, currentHash);
        }

    }
}
