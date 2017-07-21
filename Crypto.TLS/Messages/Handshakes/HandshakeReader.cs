using System;
using System.IO;
using Crypto.Certificates;
using Crypto.Certificates.Services;
using Crypto.TLS.Config;
using Crypto.TLS.Records;
using Crypto.TLS.Services;
using Crypto.Utils;
using Crypto.Utils.IO;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TLS.Messages.Handshakes
{
    public class HandshakeReader
    {
        private readonly IServiceProvider _serviceProvider;

        private readonly HandshakeConfig _handshakeConfig;
        private readonly CipherSuiteConfig _cipherSuiteConfig;

        public HandshakeReader(
            IServiceProvider serviceProvider,

            HandshakeConfig handshakeConfig,
            CipherSuiteConfig cipherSuiteConfig)
        {
            _serviceProvider = serviceProvider;

            _handshakeConfig = handshakeConfig;
            _cipherSuiteConfig = cipherSuiteConfig;
        }

        public HandshakeMessage Read(Record record)
        {
            SecurityAssert.Assert(record.Type == RecordType.Handshake);

            using (var ms = new MemoryStream(record.Data))
            {
                var msReader = new EndianBinaryReader(EndianBitConverter.Big, ms);

                var type = msReader.ReadHandshakeType();
                var length = msReader.ReadUInt24();

                if (record.Length - 4 < length) { throw new NotImplementedException("Record fragmentation"); }

                var body = msReader.ReadBytes((int)length);
                var message = Read(type, body);

                _handshakeConfig.UpdateVerification(type, length, body);

                return message;
            }
        }

        private HandshakeMessage Read(HandshakeType type, byte[] body)
        {
            switch (type)
            {
                case HandshakeType.ClientHello:
                    return ClientHelloMessage.Read(body);
                case HandshakeType.ServerHello:
                    return ServerHelloMessage.Read(body);
                case HandshakeType.Certificate:
                    return CertificateMessage.Read(body, b => new X509Reader(_serviceProvider.GetRequiredService<PublicKeyReaderRegistry>(), _serviceProvider, b));
                case HandshakeType.ServerKeyExchange:
                    return new ServerKeyExchangeMessage(body);
                case HandshakeType.ServerHelloDone:
                    return ServerHelloDoneMessage.Read(body);
                case HandshakeType.ClientKeyExchange:
                    return new ClientKeyExchangeMessage(body);
                case HandshakeType.Finished:
                    return ReadFinished(body);
                default:
                    throw new ArgumentOutOfRangeException(nameof(type), type, null);
            }
        }

        private HandshakeMessage ReadFinished(byte[] body)
        {
            var prfDigest = _serviceProvider.ResolvePRFHash(_cipherSuiteConfig.CipherSuite);
            var hash = _handshakeConfig.ComputeVerification(prfDigest);

            return FinishedMessage.Read(body, hash);
        }
    }
}
