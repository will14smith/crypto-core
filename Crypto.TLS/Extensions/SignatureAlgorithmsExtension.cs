using System.Collections.Generic;
using System.IO;
using Crypto.TLS.Config;
using Crypto.TLS.Identifiers;
using Crypto.TLS.Messages.Handshakes;
using Crypto.Utils;
using Crypto.Utils.IO;
using System.Linq;
using Crypto.TLS.Suites;
using Crypto.TLS.Suites.Providers;
using Crypto.TLS.Suites.Registries;

namespace Crypto.TLS.Extensions
{
    public class SignatureAlgorithmsExtension : IExtension
    {       
        private readonly ICipherSuitesProvider _cipherSuiteProvider;
        private readonly CipherSuitesRegistry _cipherSuitesRegistry;

        private readonly HashAlgorithmRegistry _hashAlgorithmRegistry;
        private readonly SignatureAlgorithmsRegistry _signatureAlgorithmsRegistry;
        
        private readonly EndConfig _endConfig;
        private readonly Config _config;

        public SignatureAlgorithmsExtension(
            ICipherSuitesProvider cipherSuiteProvider,
            CipherSuitesRegistry cipherSuitesRegistry,

            HashAlgorithmRegistry hashAlgorithmRegistry,
            SignatureAlgorithmsRegistry signatureAlgorithmsRegistry,

            EndConfig endConfig,
            Config config)
        {
            _cipherSuiteProvider = cipherSuiteProvider;
            _cipherSuitesRegistry = cipherSuitesRegistry;

            _hashAlgorithmRegistry = hashAlgorithmRegistry;
            _signatureAlgorithmsRegistry = signatureAlgorithmsRegistry;

            _endConfig = endConfig;
            _config = config;
        }

        public IEnumerable<HelloExtension> GenerateHelloExtensions()
        {
            if (_endConfig.End == ConnectionEnd.Server)
            {
                yield break;
            }

            var suites = _cipherSuiteProvider
                .GetAllSupportedSuites(_cipherSuitesRegistry);

            _config.SupportedAlgorithms = suites
                .Select(x => (_cipherSuitesRegistry.MapHashAlgorithm(x), _cipherSuitesRegistry.MapSignatureAlgorithm(x)))
                .Distinct()
                .ToArray();
           
            using (var ms = new MemoryStream())
            {
                var writer = new EndianBinaryWriter(EndianBitConverter.Big, ms);

                writer.Write((ushort)(_config.SupportedAlgorithms.Count * 2));
                foreach (var (hash, sig) in _config.SupportedAlgorithms)
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

            _config.SupportedAlgorithms = algorithms.Where(IsSupported).ToList();
        }

        private bool IsSupported((TLSHashAlgorithm, TLSSignatureAlgorithm) algorithms)
        {
            var (hash, sig) = algorithms;

            return _hashAlgorithmRegistry.IsSupported(hash)
                   && _signatureAlgorithmsRegistry.IsSupported(sig);
        }

        public class Config
        {
            public IReadOnlyCollection<(TLSHashAlgorithm, TLSSignatureAlgorithm)> SupportedAlgorithms { get; internal set; }
        }
    }
}