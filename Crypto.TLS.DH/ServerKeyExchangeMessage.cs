using System;
using System.Numerics;
using Crypto.Core.Signing;
using Crypto.TLS.Config;
using Crypto.TLS.Messages.Handshakes;
using Crypto.TLS.Services;
using Crypto.Utils;
using Crypto.Utils.IO;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TLS.DH
{
    public class ServerKeyExchangeMessage : HandshakeMessage
    {
        private readonly IServiceProvider _serviceProvider;

        public BigInteger P { get; }
        public BigInteger G { get; }
        public BigInteger Ys { get; }

        public ServerKeyExchangeMessage(
            IServiceProvider serviceProvider,
            BigInteger p, BigInteger g, BigInteger ys)
            : base(HandshakeType.ServerKeyExchange)
        {
            _serviceProvider = serviceProvider;
            
            P = p;
            G = g;
            Ys = ys;
        }

        protected override void Write(EndianBinaryWriter baseWriter)
        {
            var cipherSuiteConfig = _serviceProvider.GetRequiredService<CipherSuiteConfig>();
            
            var stream = CreateSignedStream(baseWriter, cipherSuiteConfig);
            var writer = new EndianBinaryWriter(baseWriter.BitConverter, stream);

            var randomConfig = _serviceProvider.GetRequiredService<RandomConfig>();

            // signature needs these but the output doesn't
            stream.HashAlgorithm.Update(randomConfig.Client, 0, 32);
            stream.HashAlgorithm.Update(randomConfig.Server, 0, 32);

            var pBuffer = P.ToByteArray(Endianness.BigEndian);
            var gBuffer = G.ToByteArray(Endianness.BigEndian);
            var pubBuffer = Ys.ToByteArray(Endianness.BigEndian);

            writer.Write((short)pBuffer.Length);
            writer.Write(pBuffer);
            writer.Write((short)gBuffer.Length);
            writer.Write(gBuffer);
            writer.Write((short)pubBuffer.Length);
            writer.Write(pubBuffer);

            stream.Flush();

            var cipherSuites = _serviceProvider.GetRequiredService<CipherSuiteRegistry>();

            stream.WriteTlsSignature(
                cipherSuites.ResolveHashAlgorithm(cipherSuiteConfig.CipherSuite),
                cipherSuites.ResolveSignatureAlgorithm(cipherSuiteConfig.CipherSuite));
        }

        private SignedStream CreateSignedStream(EndianBinaryWriter baseWriter, CipherSuiteConfig cipherSuiteConfig)
        {
            var signature = _serviceProvider.ResolveSignatureAlgorithm(cipherSuiteConfig.CipherSuite);
            var signatureCipherFactory = _serviceProvider.ResolveSignatureCipherParameterFactory(cipherSuiteConfig.CipherSuite);
            var digest = _serviceProvider.ResolveHashAlgorithm(cipherSuiteConfig.CipherSuite);

            var endConfig = _serviceProvider.GetRequiredService<EndConfig>();

            signature.Init(signatureCipherFactory.Create(endConfig.End, ConnectionDirection.Write));

            return new SignedStream(baseWriter.BaseStream, signature, digest);
        }
    }
}