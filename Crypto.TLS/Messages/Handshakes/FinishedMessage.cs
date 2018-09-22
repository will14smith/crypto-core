using System;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.TLS.Messages.Handshakes
{
    public class FinishedMessage : HandshakeMessage
    {
        // TODO could in theory not be 12...
        public const int VerifyDataLength = 12; 
        
        public ReadOnlyMemory<byte> VerifyActual { get; }
        public ReadOnlyMemory<byte> VerifyExpectedHash { get; }

        public FinishedMessage(ReadOnlySpan<byte> verifyActual, ReadOnlySpan<byte> verifyExpectedHash) : base(HandshakeType.Finished)
        {
            SecurityAssert.Assert(verifyActual.Length == VerifyDataLength);

            VerifyActual = verifyActual.ToArray();
            VerifyExpectedHash = verifyExpectedHash.ToArray();
        }

        protected override void Write(EndianBinaryWriter writer)
        {
            writer.Write(VerifyActual);
        }

        public static HandshakeMessage Read(ReadOnlySpan<byte> body, ReadOnlySpan<byte> currentHash)
        {
            SecurityAssert.Assert(body.Length == VerifyDataLength);

            return new FinishedMessage(body.Slice(0, VerifyDataLength), currentHash);
        }
    }
}
