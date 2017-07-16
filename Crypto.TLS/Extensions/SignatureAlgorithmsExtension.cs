using System;
using System.Collections.Generic;
using Crypto.TLS.Config;
using Crypto.TLS.Identifiers;
using Crypto.TLS.Messages.Handshakes;
using Crypto.Utils;

namespace Crypto.TLS.Extensions
{
    public class SignatureAlgorithmsExtension : IExtension
    {
        private readonly EndConfig _endConfig;
        private readonly Config _config;

        public SignatureAlgorithmsExtension(EndConfig endConfig, Config config)
        {
            _endConfig = endConfig;
            _config = config;
        }

        public IEnumerable<HelloExtension> GenerateHelloExtensions()
        {
            if (_endConfig.End == ConnectionEnd.Server)
            {
                yield break;
            }

            throw new NotImplementedException();
        }

        public void HandleHello(HelloExtension hello)
        {
            SecurityAssert.Assert(_endConfig.End == ConnectionEnd.Server);

            var algorithms = new List<(TLSHashAlgorithm, TLSSignatureAlgorithm)>();

            var length = EndianBitConverter.Big.ToUInt16(hello.Data, 0);
            SecurityAssert.Assert(length % 2 == 0 && length >= 4);

            var count = length / 2;
            for (var i = 0; i < count; i++)
            {
                var hash = (TLSHashAlgorithm)hello.Data[2 * i + 2];
                var sig = (TLSSignatureAlgorithm)hello.Data[2 * i + 3];

                algorithms.Add((hash, sig));
            }

            _config.SupportedAlgorithms = algorithms;
        }

        public class Config
        {
            public IReadOnlyCollection<(TLSHashAlgorithm, TLSSignatureAlgorithm)> SupportedAlgorithms { get; internal set; }
        }
    }
}