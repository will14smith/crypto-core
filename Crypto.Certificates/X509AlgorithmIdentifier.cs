using System.Collections.Generic;
using System.Linq;
using Crypto.ASN1;
using Crypto.Utils;

namespace Crypto.Certificates
{
    public class X509AlgorithmIdentifier
    {
        public X509AlgorithmIdentifier(ASN1ObjectIdentifier algorithm, IEnumerable<ASN1Object> parameters)
        {
            Algorithm = algorithm;
            Parameters = parameters.ToList();
        }

        public static X509AlgorithmIdentifier FromObject(ASN1Object asn1)
        {
            var seq = asn1 as ASN1Sequence;
            SecurityAssert.NotNull(seq);
            SecurityAssert.Assert(seq.Count >= 1);

            var algorithmOid = seq.Elements[0] as ASN1ObjectIdentifier;
            SecurityAssert.NotNull(algorithmOid);
            var parameters = seq.Elements.Skip(1).ToList();

            return new X509AlgorithmIdentifier(algorithmOid, parameters);
        }


        public ASN1ObjectIdentifier Algorithm { get; }
        public IReadOnlyList<ASN1Object> Parameters { get; }
    }
}