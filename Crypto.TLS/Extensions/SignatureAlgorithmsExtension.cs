using System.Collections.Generic;
using System.IO;
using System.Linq;
using Crypto.TLS.Config;
using Crypto.TLS.Identifiers;
using Crypto.TLS.Messages.Handshakes;
using Crypto.TLS.Services;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.TLS.Extensions
{
    public class SignatureAlgorithmsExtension : IExtension
    {
        private readonly CipherSuiteRegistry _cipherSuiteRegistry;

        private readonly EndConfig _endConfig;
        private readonly Config _config;

        public SignatureAlgorithmsExtension(
            CipherSuiteRegistry cipherSuiteRegistry,

            EndConfig endConfig,
            Config config)
        {
            _cipherSuiteRegistry = cipherSuiteRegistry;

            _endConfig = endConfig;
            _config = config;
        }

        public IEnumerable<HelloExtension> GenerateHelloExtensions()
        {
            if (_endConfig.End == ConnectionEnd.Server)
            {
                yield break;
            }

            var suites = _cipherSuiteRegistry.GetAll();

            var combos = suites
                .Select(x => (_cipherSuiteRegistry.ResolveHashAlgorithm(x), _cipherSuiteRegistry.ResolveSignatureAlgorithm(x)))
                .Distinct()
                .ToArray();

            using (var ms = new MemoryStream())
            {
                var writer = new EndianBinaryWriter(EndianBitConverter.Big, ms);

                writer.Write((ushort)(combos.Length * 2));
                foreach (var (hash, sig) in combos)
                {
                    writer.Write(hash.Id);
                    writer.Write(sig.Id);
                }

                yield return new HelloExtension(ExtensionType.SignatureAlgorithms, ms.ToArray());
            }
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