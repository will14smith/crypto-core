using System;
using Crypto.Utils.IO;

namespace Crypto.TLS.Messages.Handshakes
{
    public class CertificateRequestMessage :  HandshakeMessage
    {
        // TODO
        public CertificateRequestMessage() : base(HandshakeType.CertificateRequest)
        {
        }

        protected override void Write(EndianBinaryWriter writer)
        {
            throw new NotImplementedException();
        }
    }
}
