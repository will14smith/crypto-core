using System;
using System.Collections.Generic;
using System.Linq;
using Crypto.Core.Encryption;
using Crypto.Core.Encryption.Adapters;
using Crypto.TLS.Records.Strategy;
using Crypto.TLS.Suites.Providers;
using Crypto.TLS.Suites.Registries;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TLS.Suites
{
    public static class CipherSuiteRegistryExtensions
    {
        public static IReadOnlyCollection<CipherSuite> GetAllSupportedSuites(this ICipherSuitesProvider cipherSuiteProvider, CipherSuitesRegistry cipherSuitesRegistry)
        {
            var suites = cipherSuitesRegistry.GetAll();
            
            return suites
                .Where(cipherSuiteProvider.IsSupported)
                .OrderByDescending(x => x)
                .ToList();
        }
        
        public static bool IsBlockCipher(this ICipherSuitesProvider cipherSuiteProvider, CipherSuite cipherSuite)
        {
            var cipherAlgorithm = cipherSuiteProvider.ResolveCipherAlgorithm(cipherSuite);
            return cipherAlgorithm is BlockCipherAdapter || cipherAlgorithm is IBlockCipher;
        }
        public static bool IsAEADCipher(this ICipherSuitesProvider cipherSuiteProvider, CipherSuite cipherSuite)
        {
            var cipherAlgorithm = cipherSuiteProvider.ResolveCipherAlgorithm(cipherSuite);
            return cipherAlgorithm is AEADCipherAdapter || cipherAlgorithm is IAEADBlockCipher;
        }

        public static IRecordReaderStrategy GetRecordReaderStrategy(
            this ICipherSuitesProvider cipherSuiteProvider,
            IServiceProvider serviceProvider,
            CipherSuite cipherSuite)
        {
            if (cipherSuiteProvider.IsBlockCipher(cipherSuite))
            {
                return serviceProvider.GetRequiredService<BlockCipherStrategy>();
            }
            if (cipherSuiteProvider.IsAEADCipher(cipherSuite))
            {
                return serviceProvider.GetRequiredService<AEADCipherStrategy>();
            }

            return serviceProvider.GetRequiredService<CipherStrategy>();
        }
        public static IRecordWriterStrategy GetRecordWriterStrategy(
            this ICipherSuitesProvider cipherSuiteProvider,
            IServiceProvider serviceProvider,
            CipherSuite cipherSuite)
        {
            if (cipherSuiteProvider.IsBlockCipher(cipherSuite))
            {
                return serviceProvider.GetRequiredService<BlockCipherStrategy>();
            }
            if (cipherSuiteProvider.IsAEADCipher(cipherSuite))
            {
                return serviceProvider.GetRequiredService<AEADCipherStrategy>();
            }

            return serviceProvider.GetRequiredService<CipherStrategy>();
        }

    }
}