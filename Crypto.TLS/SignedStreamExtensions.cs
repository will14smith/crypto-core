using System;
using Crypto.Core.Signing;
using Crypto.TLS.Identifiers;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.TLS
{
    public static class SignedStreamExtensions
    {
        public static void WriteTlsSignature(this SignedStream stream, TLSHashAlgorithm hashAlgorithm, TLSSignatureAlgorithm signatureAlgorithm)
        {
            stream.InnerStream.Write(new[]
            {
                hashAlgorithm.Id,
                signatureAlgorithm.Id
            }, 0, 2);

            var signature = stream.Sign();

            stream.InnerStream.Write(EndianBitConverter.Big.GetBytes((ushort)signature.Length));
            stream.InnerStream.Write(signature);
        }
        
        public static void VerifyTlsSignature(this SignedStream stream, TLSHashAlgorithm hashAlgorithm, TLSSignatureAlgorithm signatureAlgorithm)
        {
            var reader = new EndianBinaryReader(EndianBitConverter.Big, stream.InnerStream);

            var actualHashAlgo = reader.ReadByte();
            SecurityAssert.Assert(actualHashAlgo == hashAlgorithm.Id);
            var actualSignAlgo = reader.ReadByte();
            SecurityAssert.Assert(actualSignAlgo == signatureAlgorithm.Id);
            
            var signLength = reader.ReadUInt16();
            var actualSign = reader.ReadBytes(signLength);
            SecurityAssert.Assert(stream.Verify(actualSign));
        }
    }
}
