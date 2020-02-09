using System;
using Crypto.Core.Hashing;
using Crypto.TLS.Config;
using Crypto.TLS.EC.KeyExchanges;
using Crypto.TLS.Messages.Handshakes;
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

            if (randomConfig.Client is null || randomConfig.Server is null)
            {
                throw new InvalidOperationException("Random config is not initialized");
            }
            
            // signature needs these but the output doesn't
            stream.HashAlgorithm.Update(randomConfig.Client.AsSpan(0, 32));
            stream.HashAlgorithm.Update(randomConfig.Server.AsSpan(0, 32));

            Parameters.Write(writer);

            stream.Flush();

            stream.WriteTlsSignature(hashAlgorithm, signatureAlgorithm);
        }
    }
}
