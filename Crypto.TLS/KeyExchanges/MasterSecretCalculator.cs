using System;
using System.Linq;
using Crypto.TLS.Config;
using Crypto.TLS.Hashing;
using Crypto.TLS.Services;
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

        public byte[] Compute(byte[] preMasterSecret)
        {
            var clientRandom = _randomConfig.Client;
            var serverRandom = _randomConfig.Server;

            var random = new byte[clientRandom.Length + serverRandom.Length];

            Array.Copy(clientRandom, 0, random, 0, clientRandom.Length);
            Array.Copy(serverRandom, 0, random, clientRandom.Length, serverRandom.Length);

            var prfDigest = _cipherSuitesProvider.ResolvePRFHash(_cipherSuiteConfig.CipherSuite);
            var prf = new PRF(prfDigest);

            return prf.Digest(preMasterSecret, "master secret", random).Take(48).ToArray();
        }

        public void ComputeKeysAndUpdateConfig(byte[] masterSecret)
        {
            _keyConfig.Master = masterSecret;
            Console.WriteLine(HexConverter.ToHex(_keyConfig.Master));

            var cipherSuite = _cipherSuiteConfig.CipherSuite;

            var clientRandom = _randomConfig.Client;
            var serverRandom = _randomConfig.Server;

            var cipher = _cipherSuitesProvider.ResolveCipherAlgorithm(cipherSuite);
            var mac = _cipherSuitesProvider.ResolveHashAlgorithm(cipherSuite);

            var prfDigest = _cipherSuitesProvider.ResolvePRFHash(_cipherSuiteConfig.CipherSuite);
            var prf = new PRF(prfDigest);

            var random = new byte[serverRandom.Length + clientRandom.Length];

            Array.Copy(serverRandom, 0, random, 0, serverRandom.Length);
            Array.Copy(clientRandom, 0, random, serverRandom.Length, clientRandom.Length);

            var macKeyLength = mac.HashSize / 8;
            var encKeyLength = cipher.KeySize;
            // for AEAD - TODO is it constant?
            var implicitIVLength = 4;

            var keyBlockLength = 2 * macKeyLength + 2 * encKeyLength + 2 * implicitIVLength;

            var keyBlock = prf.Digest(masterSecret, "key expansion", random).Take(keyBlockLength).ToArray();

            var offset = 0;

            // TODO technically AEAD has no mac (i.e. length == 0)
            if (!_cipherSuitesProvider.IsAEADCipher(cipherSuite))
            {
                var clientMACKey = new byte[macKeyLength];
                Array.Copy(keyBlock, offset, clientMACKey, 0, macKeyLength);
                offset += macKeyLength;
                _blockConfig.ClientMACKey = clientMACKey;

                var serverMACKey = new byte[macKeyLength];
                Array.Copy(keyBlock, offset, serverMACKey, 0, macKeyLength);
                offset += macKeyLength;
                _blockConfig.ServerMACKey = serverMACKey;
            }

            var clientKey = new byte[encKeyLength];
            Array.Copy(keyBlock, offset, clientKey, 0, encKeyLength);
            offset += encKeyLength;
            _keyConfig.Client = clientKey;

            var serverKey = new byte[encKeyLength];
            Array.Copy(keyBlock, offset, serverKey, 0, encKeyLength);
            offset += encKeyLength;
            _keyConfig.Server = serverKey;
            
            if (_cipherSuitesProvider.IsAEADCipher(cipherSuite))
            {
                var clientIV = new byte[implicitIVLength];
                Array.Copy(keyBlock, offset, clientIV, 0, implicitIVLength);
                offset += implicitIVLength;
                _aeadConfig.ClientIV = clientIV;

                var serverIV = new byte[implicitIVLength];
                Array.Copy(keyBlock, offset, serverIV, 0, implicitIVLength);
                offset += implicitIVLength;
                _aeadConfig.ServerIV = serverIV;
            }
        }
    }
}
