using System;
using System.Collections;
using System.IO;
using Crypto.ASN1;
using Crypto.Certificates;
using Crypto.Certificates.Keys;
using Crypto.Utils;

namespace Crypto.TLS.DH.Keys
{
    public class DHKeyReader : IPublicKeyReader, IPrivateKeyReader
    {
        public PublicKey ReadPublicKey(X509AlgorithmIdentifier algorithm, BitArray bits)
        {
            return CreatePublicKey(algorithm);
        }

        public PrivateKey ReadPrivateKey(X509AlgorithmIdentifier algorithm, byte[] input)
        {
            using (var ms = new MemoryStream(input))
            {
                var asn1 = new DERReader(ms);

                return new DHPrivateKey(CreatePublicKey(algorithm), asn1.Read());
            }
        }
        
        private static PublicKey CreatePublicKey(X509AlgorithmIdentifier algorithm)
        {
            SecurityAssert.Assert(algorithm.Algorithm == DHIdentifiers.DHKeyAgreement);
            SecurityAssert.Assert(algorithm.Parameters.Count == 1);

            var keySeq = algorithm.Parameters[0] as ASN1Sequence;
            SecurityAssert.Assert(keySeq != null && keySeq.Count == 2);

            var p = keySeq.Elements[0] as ASN1Integer;
            SecurityAssert.NotNull(p);
            var g = keySeq.Elements[1] as ASN1Integer;
            SecurityAssert.NotNull(g);

            return new DHPublicKey(p.Value, g.Value);
        }
    }
}
