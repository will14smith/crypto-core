using System;
using Crypto.Core.Encryption;
using Crypto.Core.Encryption.Adapters;
using Crypto.TLS.Records.Strategy;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TLS.Services
{
    public static class CipherSuitesExtensions
    {
        public static bool IsBlockCipher(this IServiceProvider serviceProvider, CipherSuite cipherSuite)
        {
            var cipherAlgorithm = serviceProvider.ResolveCipherAlgorithm(cipherSuite);
            return cipherAlgorithm is BlockCipherAdapter || cipherAlgorithm is IBlockCipher;
        }
        public static bool IsAEADCipher(this IServiceProvider serviceProvider, CipherSuite cipherSuite)
        {
            var cipherAlgorithm = serviceProvider.ResolveCipherAlgorithm( cipherSuite);
            return cipherAlgorithm is AEADCipherAdapter || cipherAlgorithm is IAEADBlockCipher;
        }

        public static IRecordReaderStrategy GetRecordReaderStrategy(
            this IServiceProvider serviceProvider,
            CipherSuite cipherSuite)
        {
            if (serviceProvider.IsBlockCipher(cipherSuite))
            {
                return serviceProvider.GetRequiredService<BlockCipherStrategy>();
            }
            if (serviceProvider.IsAEADCipher(cipherSuite))
            {
                return serviceProvider.GetRequiredService<AEADCipherStrategy>();
            }

            throw new NotImplementedException();
        }
        public static IRecordWriterStrategy GetRecordWriterStrategy(
            this IServiceProvider serviceProvider,
            CipherSuite cipherSuite)
        {
            if (serviceProvider.IsBlockCipher(cipherSuite))
            {
                return serviceProvider.GetRequiredService<BlockCipherStrategy>();
            }
            if (serviceProvider.IsAEADCipher(cipherSuite))
            {
                return serviceProvider.GetRequiredService<AEADCipherStrategy>();
            }

            throw new NotImplementedException();
        }
    }
}
