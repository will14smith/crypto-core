using Crypto.Core.Signing;
using Crypto.TLS.Identifiers;
using Crypto.Utils;

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

            stream.InnerStream.Write(EndianBitConverter.Big.GetBytes((ushort)signature.Length), 0, 2);
            stream.InnerStream.Write(signature, 0, signature.Length);
        }
    }
}
