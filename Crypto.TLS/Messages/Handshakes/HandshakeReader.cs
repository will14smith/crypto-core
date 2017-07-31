using System;
using System.IO;
using Crypto.Certificates;
using Crypto.Certificates.Services;
using Crypto.TLS.Config;
using Crypto.TLS.Records;
using Crypto.TLS.Services;
using Crypto.TLS.Suites.Providers;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.TLS.Messages.Handshakes
{
    public class HandshakeReader
    {
        private readonly ICipherSuitesProvider _cipherSuitesProvider;
        private readonly PublicKeyReaderRegistry _publicKeyReaderRegistry;

        private readonly HandshakeConfig _handshakeConfig;
        private readonly CipherSuiteConfig _cipherSuiteConfig;

        public HandshakeReader(
            ICipherSuitesProvider cipherSuitesProvider,
            PublicKeyReaderRegistry publicKeyReaderRegistry,

            HandshakeConfig handshakeConfig,
            CipherSuiteConfig cipherSuiteConfig)
        {
            _cipherSuitesProvider = cipherSuitesProvider;
            _publicKeyReaderRegistry = publicKeyReaderRegistry;

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
                    return CertificateMessage.Read(body, b => new X509Reader(_publicKeyReaderRegistry, b));
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
            var prfDigest = _cipherSuitesProvider.ResolvePRFHash(_cipherSuiteConfig.CipherSuite);
            var hash = _handshakeConfig.ComputeVerification(prfDigest);

            return FinishedMessage.Read(body, hash);
        }
    }
}
