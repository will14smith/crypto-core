using System;
using Crypto.TLS.Config;
using Crypto.TLS.EC.KeyExchanges;
using Crypto.TLS.Messages.Handshakes;
using Crypto.TLS.Services;
using Crypto.Utils.IO;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TLS.EC
{
    public class ECServerKeyExchangeMessage : HandshakeMessage
    {
        private readonly IServiceProvider _serviceProvider;

        public ServerECDHParams Parameters { get; }

        public ECServerKeyExchangeMessage(
            IServiceProvider serviceProvider,
            ServerECDHParams parameters)
            : base(HandshakeType.ServerKeyExchange)
        {
            _serviceProvider = serviceProvider;
            Parameters = parameters;
        }

        protected override void Write(EndianBinaryWriter baseWriter)
        {
            var (hashAlgorithm, signatureAlgorithm) = _serviceProvider.GetSigningAlgorithms();

            var stream = _serviceProvider.CreateSignedStream(baseWriter.BaseStream, hashAlgorithm, signatureAlgorithm);
            var writer = new EndianBinaryWriter(baseWriter.BitConverter, stream);

            var randomConfig = _serviceProvider.GetRequiredService<RandomConfig>();

            // signature needs these but the output doesn't
            stream.HashAlgorithm.Update(randomConfig.Client);
            stream.HashAlgorithm.Update(randomConfig.Server);

            Parameters.Write(writer);

            stream.Flush();

            stream.WriteTlsSignature(hashAlgorithm, signatureAlgorithm);
        }
    }
}
