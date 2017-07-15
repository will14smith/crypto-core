using System;
using System.Collections;
using System.Collections.Generic;
using Crypto.Certificates.Keys;
using Crypto.Certificates.Services;

namespace Crypto.Certificates
{
    public class CertificateManager
    {
        // TODO this is really insecure...

        private readonly List<X509Certificate> _certificates;
        private readonly Dictionary<PublicKey, PrivateKey> _keys;
        private X509Certificate _defaultCertificate;

        private readonly IServiceProvider _serviceProvider;
        private readonly PublicKeyReaderRegistry _publicKeyReaderRegistry;
        private readonly PrivateKeyReaderRegistry _privateKeyReaderRegistry;

        public CertificateManager(
            IServiceProvider serviceProvider,
            PublicKeyReaderRegistry publicKeyReaderRegistry,
            PrivateKeyReaderRegistry privateKeyReaderRegistry)
        {
            _serviceProvider = serviceProvider;
            _publicKeyReaderRegistry = publicKeyReaderRegistry;
            _privateKeyReaderRegistry = privateKeyReaderRegistry;

            _certificates = new List<X509Certificate>();
            _keys = new Dictionary<PublicKey, PrivateKey>();
        }

        public void AddCertificate(byte[] input)
        {
            var reader = new X509Reader(_publicKeyReaderRegistry, _serviceProvider, input);
            var cert = reader.ReadCertificate();

            if (_certificates.Count == 0)
            {
                _defaultCertificate = cert;
            }

            _certificates.Add(cert);
        }
        public void AddPrivateKey(byte[] input)
        {
            var reader = new PrivateKeyReader(_privateKeyReaderRegistry);
            var key = reader.ReadKey(_serviceProvider, input);

            _keys.Add(key.PublicKey, key);
        }

        public X509Certificate GetDefaultCertificate()
        {
            return _defaultCertificate;
        }

        public IReadOnlyCollection<X509Certificate> GetAllCertificates()
        {
            return _certificates;
        }

        public PrivateKey GetPrivateKey(PublicKey publicKey)
        {
            PrivateKey privateKey;
            if (!_keys.TryGetValue(publicKey, out privateKey))
            {
                throw new KeyNotFoundException();
            }

            return privateKey;
        }
    }
}
