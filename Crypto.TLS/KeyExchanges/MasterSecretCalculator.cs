using System;
using System.Linq;
using Crypto.TLS.Config;
using Crypto.TLS.Hashing;
using Crypto.TLS.Suites;
using Crypto.TLS.Suites.Providers;
using Crypto.Utils;

namespace Crypto.TLS.KeyExchanges
{
    public class MasterSecretCalculator
    {
        private readonly ICipherSuitesProvider _cipherSuitesProvider;

        private readonly RandomConfig _randomConfig;
        private readonly CipherSuiteConfig _cipherSuiteConfig;

        private readonly KeyConfig _keyConfig;
        private readonly AEADCipherConfig _aeadConfig;
        private readonly BlockCipherConfig _blockConfig;

        public MasterSecretCalculator(
            ICipherSuitesProvider cipherSuitesProvider,

            RandomConfig randomConfig,
            CipherSuiteConfig cipherSuiteConfig,

            KeyConfig keyConfig,
            AEADCipherConfig aeadConfig,
            BlockCipherConfig blockConfig)
        {
            _cipherSuitesProvider = cipherSuitesProvider;

            _randomConfig = randomConfig;
            _cipherSuiteConfig = cipherSuiteConfig;

            _keyConfig = keyConfig;
            _aeadConfig = aeadConfig;
            _blockConfig = blockConfig;
        }

        public ReadOnlySpan<byte> Compute(ReadOnlySpan<byte> preMasterSecret)
        {
            var clientRandom = _randomConfig.Client;
            var serverRandom = _randomConfig.Server;

            var random = new byte[clientRandom.Length + serverRandom.Length];
            clientRandom.CopyTo(random);
            serverRandom.CopyTo(random.AsMemory(clientRandom.Length));

            var prfDigest = _cipherSuitesProvider.ResolvePRFHash(_cipherSuiteConfig.CipherSuite);
            var prf = new PRF(prfDigest);

            return prf.Digest(preMasterSecret.ToArray(), "master secret", random).Take(48).ToArray();
        }

        public void ComputeKeysAndUpdateConfig(ReadOnlySpan<byte> masterSecret)
        {
            _keyConfig.Master = masterSecret.ToArray();

            var cipherSuite = _cipherSuiteConfig.CipherSuite;

            var clientRandom = _randomConfig.Client;
            var serverRandom = _randomConfig.Server;

            var cipher = _cipherSuitesProvider.ResolveCipherAlgorithm(cipherSuite);
            var mac = _cipherSuitesProvider.ResolveHashAlgorithm(cipherSuite);

            var prfDigest = _cipherSuitesProvider.ResolvePRFHash(_cipherSuiteConfig.CipherSuite);
            var prf = new PRF(prfDigest);

            var random = new byte[serverRandom.Length + clientRandom.Length];
            serverRandom.CopyTo(random);
            clientRandom.CopyTo(random.AsMemory(serverRandom.Length));

            var macKeyLength = mac.HashSize / 8;
            var encKeyLength = cipher.KeySize;
            // for AEAD - TODO is it constant?
            var implicitIVLength = 4;

            var keyBlockLength = 2 * macKeyLength + 2 * encKeyLength + 2 * implicitIVLength;

            var keyBlock = prf.Digest(masterSecret.ToArray(), "key expansion", random).Take(keyBlockLength).ToArray().AsMemory();

            // TODO technically AEAD has no mac (i.e. length == 0)
            if (!_cipherSuitesProvider.IsAEADCipher(cipherSuite))
            {
                (_blockConfig.ClientMACKey, keyBlock) = keyBlock.Split(macKeyLength);
                (_blockConfig.ServerMACKey, keyBlock) = keyBlock.Split(macKeyLength);
            }

            (_keyConfig.Client, keyBlock) = keyBlock.Split(encKeyLength);
            (_keyConfig.Server, keyBlock) = keyBlock.Split(encKeyLength);

            if (_cipherSuitesProvider.IsAEADCipher(cipherSuite))
            {
                (_aeadConfig.ClientIV, keyBlock) = keyBlock.Split(implicitIVLength);
                (_aeadConfig.ServerIV, keyBlock) = keyBlock.Split(implicitIVLength);
            }
        }
    }
}
