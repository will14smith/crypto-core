using System;
using Crypto.TLS.Config;
using Crypto.TLS.EC.KeyExchanges;
using Crypto.TLS.Messages.Handshakes;
using Crypto.TLS.Services;
using Crypto.Utils.IO;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TLS.EC
{
    public class ServerKeyExchangeMessage : HandshakeMessage
    {
        private readonly IServiceProvider _serviceProvider;

        public ServerECDHParams Parameters { get; }

        public ServerKeyExchangeMessage(
            IServiceProvider serviceProvider,
            ServerECDHParams parameters)
            : base(HandshakeType.ServerKeyExchange)
        {
            _serviceProvider = serviceProvider;
            Parameters = parameters;
        }

        protected override void Write(EndianBinaryWriter baseWriter)
        {
            var cipherSuiteConfig = _serviceProvider.GetRequiredService<CipherSuiteConfig>();
            var cipherSuites = _serviceProvider.GetRequiredService<CipherSuiteRegistry>();

            // TODO check these are compatible with signature_algorithms extension & certificate
            var hashAlgorithm = cipherSuites.ResolveHashAlgorithm(cipherSuiteConfig.CipherSuite);
            var signatureAlgorithm = cipherSuites.ResolveSignatureAlgorithm(cipherSuiteConfig.CipherSuite);

            var stream = _serviceProvider.CreateSignedStream(baseWriter, hashAlgorithm, signatureAlgorithm);
            var writer = new EndianBinaryWriter(baseWriter.BitConverter, stream);

            var randomConfig = _serviceProvider.GetRequiredService<RandomConfig>();

            // signature needs these but the output doesn't
            stream.HashAlgorithm.Update(randomConfig.Client, 0, 32);
            stream.HashAlgorithm.Update(randomConfig.Server, 0, 32);
            
            Parameters.Write(writer);
            
            stream.Flush();

            stream.WriteTlsSignature(
                cipherSuites.ResolveHashAlgorithm(cipherSuiteConfig.CipherSuite),
                signatureAlgorithm);

        }
    }
}
