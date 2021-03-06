﻿using System.Collections.Generic;
using System.Linq;
using Crypto.TLS.Identifiers;

namespace Crypto.TLS.Suites.Registries
{
    public class CipherSuitesRegistry
    {
        private readonly ISet<CipherSuite> _suites
            = new HashSet<CipherSuite>();

        private readonly Dictionary<CipherSuite, TLSCipherAlgorithm> _cipherMapping
            = new Dictionary<CipherSuite, TLSCipherAlgorithm>();
        private readonly Dictionary<CipherSuite, TLSHashAlgorithm> _hashMapping
            = new Dictionary<CipherSuite, TLSHashAlgorithm>();
        private readonly Dictionary<CipherSuite, TLSSignatureAlgorithm> _signatureMapping
            = new Dictionary<CipherSuite, TLSSignatureAlgorithm>();
        private readonly Dictionary<CipherSuite, TLSKeyExchange> _keyExchangeMapping
            = new Dictionary<CipherSuite, TLSKeyExchange>();

        public CipherSuitesRegistry()
        {
            Register(
                suite: CipherSuite.TLS_NULL_WITH_NULL_NULL,
                cipher: TLSCipherAlgorithm.Null,
                digest: TLSHashAlgorithm.None,
                signature: TLSSignatureAlgorithm.Anonymous,
                exchange: TLSKeyExchange.Null);
        }

        public void Register(
            CipherSuite suite,
            TLSCipherAlgorithm cipher,
            TLSHashAlgorithm digest,
            TLSSignatureAlgorithm signature,
            TLSKeyExchange exchange)
        {
            _suites.Add(suite);

            _cipherMapping.Add(suite, cipher);
            _hashMapping.Add(suite, digest);
            _signatureMapping.Add(suite, signature);
            _keyExchangeMapping.Add(suite, exchange);
        }

        public bool IsSupported(CipherSuite suite)
        {
            return _suites.Contains(suite);
        }

        public IReadOnlyCollection<CipherSuite> GetAll()
        {
            return _suites.ToList();
        }

        public TLSCipherAlgorithm MapCipherAlgorithm(CipherSuite suite)
        {
            return _cipherMapping[suite];
        }
        public TLSHashAlgorithm MapHashAlgorithm(CipherSuite suite)
        {
            return _hashMapping[suite];
        }
        public TLSSignatureAlgorithm MapSignatureAlgorithm(CipherSuite suite)
        {
            return _signatureMapping[suite];
        }
        public TLSKeyExchange MapKeyExchange(CipherSuite suite)
        {
            return _keyExchangeMapping[suite];
        }
    }
}
