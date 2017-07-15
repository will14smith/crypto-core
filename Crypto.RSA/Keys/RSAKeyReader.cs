using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Crypto.ASN1;
using Crypto.Certificates;
using Crypto.Certificates.Keys;
using Crypto.Utils;

namespace Crypto.RSA.Keys
{
    public class RSAKeyReader : IPublicKeyReader, IPrivateKeyReader
    {
        public static IReadOnlyCollection<ASN1ObjectIdentifier> RSAIdentifiers = new List<ASN1ObjectIdentifier>
        {
            new ASN1ObjectIdentifier("1.2.840.113549.1.1.1"),
            new ASN1ObjectIdentifier("1.2.840.113549.1.1.11"),
        };

        public static bool IsRSAIdentifier(ASN1ObjectIdentifier identifier)
        {
            return RSAIdentifiers.Contains(identifier);
        }

        public PublicKey ReadPublicKey(X509AlgorithmIdentifier algorithm, BitArray bits)
        {
            SecurityAssert.Assert(IsRSAIdentifier(algorithm.Algorithm));
            SecurityAssert.Assert(algorithm.Parameters.Count == 1 && algorithm.Parameters[0] is ASN1Null);

            var data = bits.ToArray();

            ASN1Object asn1;
            using (var ms = new MemoryStream(data))
            {
                asn1 = new DERReader(ms).Read();
            }

            var keySeq = asn1 as ASN1Sequence;
            SecurityAssert.Assert(keySeq != null && keySeq.Count == 2);

            var modulusInt = keySeq.Elements[0] as ASN1Integer;
            SecurityAssert.NotNull(modulusInt);
            var exponentInt = keySeq.Elements[1] as ASN1Integer;
            SecurityAssert.NotNull(exponentInt);

            return new RSAPublicKey(modulusInt.Value, exponentInt.Value);
        }

        public PrivateKey ReadPrivateKey(X509AlgorithmIdentifier algorithm, byte[] input)
        {
            using (var ms = new MemoryStream(input))
            {
                var asn1 = new DERReader(ms);

                return new RSAPrivateKey(asn1.Read());
            }
        }
    }
}