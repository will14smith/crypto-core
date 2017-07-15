using System;
using System.Collections;
using System.IO;
using Crypto.ASN1;
using Crypto.Certificates;
using Crypto.Certificates.Keys;
using Crypto.TLS.DH.Config;
using Crypto.Utils;

namespace Crypto.TLS.DH.Keys
{
    public class DHKeyReader : IPublicKeyReader, IPrivateKeyReader
    {
        public PublicKey ReadPublicKey(X509AlgorithmIdentifier algorithm, BitArray bits)
        {
            var parameters = CreateParameters(algorithm);

            var data = bits.ToArray();

            ASN1Object asn1;
            using (var ms = new MemoryStream(data))
            {
                asn1 = new DERReader(ms).Read();
            }

            var y = asn1 as ASN1Integer;
            SecurityAssert.NotNull(y);

            return new DHPublicKey(parameters, y.Value);
        }

        public PrivateKey ReadPrivateKey(X509AlgorithmIdentifier algorithm, byte[] input)
        {
            var parameters = CreateParameters(algorithm);

            using (var ms = new MemoryStream(input))
            {
                var asn1 = new DERReader(ms);

                return new DHPrivateKey(parameters, asn1.Read());
            }
        }

        private static DHParameterConfig CreateParameters(X509AlgorithmIdentifier algorithm)
        {
            SecurityAssert.Assert(algorithm.Algorithm == DHIdentifiers.DHKeyAgreement);
            SecurityAssert.Assert(algorithm.Parameters.Count == 1);

            var keySeq = algorithm.Parameters[0] as ASN1Sequence;
            SecurityAssert.Assert(keySeq != null && keySeq.Count == 2);

            var p = keySeq.Elements[0] as ASN1Integer;
            SecurityAssert.NotNull(p);
            var g = keySeq.Elements[1] as ASN1Integer;
            SecurityAssert.NotNull(g);

            return new DHParameterConfig(p.Value, g.Value);
        }
    }
}
