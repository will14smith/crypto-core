using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using Crypto.TLS.Config;
using Crypto.TLS.Messages.Handshakes;
using Crypto.TLS.Services;
using Crypto.Utils;
using Crypto.Utils.IO;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TLS.DH
{
    public class DHServerKeyExchangeMessage : HandshakeMessage
    {
        private readonly IServiceProvider _serviceProvider;

        public BigInteger P { get; }
        public BigInteger G { get; }
        public BigInteger Ys { get; }

        public DHServerKeyExchangeMessage(
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
            var (hashAlgorithm, signatureAlgorithm) = _serviceProvider.GetSigningAlgorithms();

            var stream = _serviceProvider.CreateSignedStream(baseWriter.BaseStream, hashAlgorithm, signatureAlgorithm);
            var writer = new EndianBinaryWriter(baseWriter.BitConverter, stream);

            var randomConfig = _serviceProvider.GetRequiredService<RandomConfig>();

            // signature needs these but the output doesn't
            stream.HashAlgorithm.Update(randomConfig.Client);
            stream.HashAlgorithm.Update(randomConfig.Server);

            var pBuffer = P.ToByteArray(Endianness.BigEndian);
            var gBuffer = G.ToByteArray(Endianness.BigEndian);
            var pubBuffer = Ys.ToByteArray(Endianness.BigEndian);

            writer.Write((ushort)pBuffer.Length);
            writer.Write(pBuffer);
            writer.Write((ushort)gBuffer.Length);
            writer.Write(gBuffer);
            writer.Write((ushort)pubBuffer.Length);
            writer.Write(pubBuffer);

            stream.Flush();

            stream.WriteTlsSignature(hashAlgorithm, signatureAlgorithm);
        }

        public static DHServerKeyExchangeMessage Read(IServiceProvider serviceProvider, IReadOnlyCollection<byte> body)
        {
            var (hashAlgorithm, signatureAlgorithm) = serviceProvider.GetSigningAlgorithms();

            using (var ms = new MemoryStream(body.ToArray()))
            {
                var stream = serviceProvider.CreateSignedStream(ms, hashAlgorithm, signatureAlgorithm);
                var reader = new EndianBinaryReader(EndianBitConverter.Big, stream);

                var randomConfig = serviceProvider.GetRequiredService<RandomConfig>();

                stream.HashAlgorithm.Update(randomConfig.Client);
                stream.HashAlgorithm.Update(randomConfig.Server);

                var plength = reader.ReadUInt16();
                var pbuffer = reader.ReadBytes(plength);
                var glength = reader.ReadUInt16();
                var gbuffer = reader.ReadBytes(glength);
                var publength = reader.ReadUInt16();
                var pubbuffer = reader.ReadBytes(publength);

                // TODO stream.VerifyTlsSignature(hashAlgorithm, signatureAlgorithm);

                return new DHServerKeyExchangeMessage(
                    serviceProvider: serviceProvider,

                    p: pbuffer.ToBigInteger(Endianness.BigEndian),
                    g: gbuffer.ToBigInteger(Endianness.BigEndian),
                    ys: pubbuffer.ToBigInteger(Endianness.BigEndian));
            }
        }
    }
}