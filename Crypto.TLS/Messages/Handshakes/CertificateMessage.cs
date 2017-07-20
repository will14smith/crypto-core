using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Crypto.Certificates;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.TLS.Messages.Handshakes
{
    public class CertificateMessage : HandshakeMessage
    {
        public CertificateMessage(IReadOnlyCollection<X509Certificate> certificates)
            : base(HandshakeType.Certificate)
        {
            SecurityAssert.NotNull(certificates);
            SecurityAssert.Assert(certificates.Count <= 0xFFFFFF);
            Certificates = certificates;
        }

        public IReadOnlyCollection<X509Certificate> Certificates { get; }

        protected override void Write(EndianBinaryWriter writer)
        {
            var certificates = Certificates.Select(GetBytes).ToArray();
            var totalLength = certificates.Sum(x => x.Length + 3);

            writer.WriteUInt24((uint)totalLength);
            foreach (var cert in certificates)
            {
                writer.WriteByteVariable(3, cert);
            }
        }

        private byte[] GetBytes(X509Certificate certificate)
        {
            using (var ms = new MemoryStream())
            {
                new X509Writer(ms).WriteCertificate(certificate);
                return ms.ToArray();
            }
        }

        public static CertificateMessage Read(byte[] body, Func<byte[], X509Reader> x509ReaderFactory)
        {
            using (var stream = new MemoryStream(body))
            {
                var reader = new EndianBinaryReader(EndianBitConverter.Big, stream);

                var certs = new List<X509Certificate>();

                var length = reader.ReadUInt24();
                while (length > 0)
                {
                    SecurityAssert.Assert(length >= 3);

                    var certLength = reader.ReadUInt24();
                    length -= 3;
                    
                    SecurityAssert.Assert(length >= certLength);
                    length -= certLength;

                    var certBytes = reader.ReadBytes((int)certLength);
                    SecurityAssert.Assert(certBytes.Length == certLength);

                    var cert = x509ReaderFactory(certBytes).ReadCertificate();
                    certs.Add(cert);
                }

                return new CertificateMessage(certs);
            }
        }
    }
}