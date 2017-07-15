using System;
using System.IO;
using Crypto.ASN1;
using Crypto.Certificates.Services;
using Crypto.Utils;

namespace Crypto.Certificates.Keys
{
    public class PrivateKeyReader
    {
        private readonly PrivateKeyReaderRegistry _keyReaderRegistry;

        public PrivateKeyReader(PrivateKeyReaderRegistry keyReaderRegistry)
        {
            _keyReaderRegistry = keyReaderRegistry;
        }

        public PrivateKey ReadKey(IServiceProvider serviceProvider, byte[] input)
        {
            // PKCS#8 only
            
            var asn1 = GetASN1(input);
            SecurityAssert.Assert(asn1.HasValue);

            var seq = asn1.Value as ASN1Sequence;
            SecurityAssert.NotNull(seq);
            SecurityAssert.Assert(seq.Count == 3);

            var version = seq.Elements[0] as ASN1Integer;
            SecurityAssert.NotNull(version);
            SecurityAssert.Assert(version.Value == 0);

            var algorithm = X509AlgorithmIdentifier.FromObject(seq.Elements[1]);
            
            var keyOctetString = seq.Elements[2] as ASN1OctetString;
            SecurityAssert.NotNull(keyOctetString);
            
            var reader = _keyReaderRegistry.Resolve(serviceProvider, algorithm.Algorithm);

            return reader.ReadPrivateKey(algorithm, keyOctetString.Value);
        }

        private Option<ASN1Object> GetASN1(byte[] input)
        {
            var pems = PEMReader.TryConvertFromBase64(input);
            if (pems.Count == 0)
            {
                return TryParseASN1(input);
            }
            if (pems.Count > 1)
            {
                return Option.None<ASN1Object>();
            }

            var pem = pems[0];
            if (pem.Name != "PRIVATE KEY")
            {
                return Option.None<ASN1Object>();
            }

            return TryParseASN1(pem.RawData);
        }

        private Option<ASN1Object> TryParseASN1(byte[] input)
        {
            using (var ms = new MemoryStream(input))
            {
                // TODO handle failure
                return Option.Some(new DERReader(ms).Read());
            }
        }
    }
}
