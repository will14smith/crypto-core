using System;
using System.Collections;
using System.IO;
using Crypto.ASN1;
using Crypto.Certificates;
using Crypto.Certificates.Keys;
using Crypto.EC.Maths;
using Crypto.EC.Maths.Prime;
using Crypto.EC.Parameters;
using Crypto.TLS.EC.Services;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.TLS.EC.Keys
{
    public class ECKeyReader : IPublicKeyReader, IPrivateKeyReader
    {
        private readonly NamedCurvesRegistry _namedCurvesRegistry;

        public ECKeyReader(NamedCurvesRegistry namedCurvesRegistry)
        {
            _namedCurvesRegistry = namedCurvesRegistry;
        }

        public PublicKey ReadPublicKey(X509AlgorithmIdentifier algorithm, BitArray bits)
        {
            var parameters = CreateParameters(algorithm);

            // TODO bits => point
            var data = bits.ToArray();
            var point = parameters.Curve.PointFromBinary(data);

            return new ECPublicKey(parameters, point);
        }

        public PrivateKey ReadPrivateKey(X509AlgorithmIdentifier algorithm, byte[] input)
        {
            var parameters = CreateParameters(algorithm);

            using (var ms = new MemoryStream(input))
            {
                var asn1 = new DERReader(ms).Read();

                var seq = asn1 as ASN1Sequence;
                SecurityAssert.NotNull(seq);
                SecurityAssert.Assert(seq.Count >= 2);

                var version = seq.Elements[0] as ASN1Integer;
                SecurityAssert.NotNull(version);
                SecurityAssert.Assert(version.Value == 1);

                var dString = seq.Elements[1] as ASN1OctetString;
                SecurityAssert.NotNull(dString);
                
                var d = parameters.Field.Int(dString.Value.ToBigInteger(Endianness.BigEndian));

                var q = Point<PrimeValue>.Multiply(
                    parameters.Curve,
                    d,
                    parameters.Generator
                );

                var pub = new ECPublicKey(parameters, q);
                
                return new ECPrivateKey(pub, d);
            }
        }

        private PrimeDomainParameters CreateParameters(X509AlgorithmIdentifier algorithm)
        {
            // TODO support other formats

            SecurityAssert.Assert(algorithm.Parameters.Count == 1);
            var curve = algorithm.Parameters[0] as ASN1ObjectIdentifier;
            SecurityAssert.NotNull(curve);

            return _namedCurvesRegistry.Resolve(curve);
        }
    }
}
