using System.Collections.Generic;
using System.IO;
using Crypto.ASN1;
using Crypto.Certificates.Services;
using Crypto.Utils;

namespace Crypto.Certificates
{
    public class X509Reader
    {
        private readonly PublicKeyReaderRegistry _keyReaderRegistry;
        private readonly byte[] _input;

        public X509Reader(PublicKeyReaderRegistry keyReaderRegistry, byte[] input)
        {
            SecurityAssert.NotNull(input);

            _keyReaderRegistry = keyReaderRegistry;
            _input = input;
        }

        // http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf for reading the DER format
        // https://www.ietf.org/rfc/rfc5280.txt for fields in certificate
        // https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem for fields in private key (PKCS#1)
        // https://lapo.it/asn1js javascript parser / visualizer

        public X509Certificate ReadCertificate()
        {
            using (var ms = new MemoryStream(_input))
            {
                var reader = new DERReader(ms);
                var asn1 = reader.Read();

                return ReadFromASN1(asn1);
            }
        }

        private X509Certificate ReadFromASN1(ASN1Object asn1)
        {
            var root = ToSeq(asn1, 3, 3);

            // TBSCert
            var tbsCertSeq = ToSeq(GetElement(root, 0), 6, 10);

            var tbsOffset = 0;
            
            byte version;

            if (tbsCertSeq.Elements[0] is ASN1Tagged)
            {
                SecurityAssert.Assert(tbsCertSeq.Elements.Count >= 7);
                
                var taggedVersion = GetElement<ASN1Tagged>(tbsCertSeq, tbsOffset++);
                SecurityAssert.Assert(taggedVersion.Tag == 0 && taggedVersion.Count == 1);
                var versionInt = GetElement<ASN1Integer>(taggedVersion, 0);
                SecurityAssert.Assert(versionInt.Value >= 0 && versionInt.Value <= 2);
                version = (byte) (versionInt.Value + 1);
            }
            else
            {
                version = 1;
            }

            var serialNumber = GetElement<ASN1Integer>(tbsCertSeq, tbsOffset++).Value;
            SecurityAssert.Assert(serialNumber >= 0);

            var signatureAlgorithm = X509AlgorithmIdentifier.FromObject(GetElement(tbsCertSeq, tbsOffset++));

            var issuer = ReadName(GetElement(tbsCertSeq, tbsOffset++));

            var validitySeq = ToSeq(GetElement(tbsCertSeq, tbsOffset++), 2, 2);
            var notBefore = GetElement(validitySeq, 0).GetTime();
            var notAfter = GetElement(validitySeq, 1).GetTime();
            var validity = new X509Validity(notBefore, notAfter);

            var subject = ReadName(GetElement(tbsCertSeq, tbsOffset++));

            var subjectPublicKeyInfo = ToSeq(GetElement(tbsCertSeq, tbsOffset++), 2, 2);
            var subjectPublicKeyAlgorithm = X509AlgorithmIdentifier.FromObject(GetElement(subjectPublicKeyInfo, 0));
            var subjectPublicKeyBits = GetElement<ASN1BitString>(subjectPublicKeyInfo, 1).Value;
            var subjectPublicKey = _keyReaderRegistry.Resolve(subjectPublicKeyAlgorithm.Algorithm).ReadPublicKey(subjectPublicKeyAlgorithm, subjectPublicKeyBits);

            var extensions = new List<X509Extension>();

            if (version >= 2)
            {
                //TODO issuerUniqueID  
                //TODO subjectUniqueID 
            }

            if (version >= 3)
            {
                var extensionsOffset = 7;
                while (true)
                {
                    if (extensionsOffset >= tbsCertSeq.Count) break;

                    var obj = GetElement(tbsCertSeq, extensionsOffset++);
                    var tagged = obj as ASN1Tagged;
                    if (tagged == null || tagged.Tag != 3)
                    {
                        continue;
                    }

                    SecurityAssert.Assert(tagged.Count == 1);

                    var extensionsSeq = ToSeq(tagged.Elements[0]);
                    extensions = ReadExtensions(extensionsSeq);

                    break;
                }
            }

            // TODO check root[1] == signature

            // TODO read & store signature
            var signature = GetElement<ASN1BitString>(root, 2).Value;

            return new X509Certificate(version, serialNumber, validity, issuer, subject, subjectPublicKeyAlgorithm, subjectPublicKey, signatureAlgorithm, signature, extensions);
        }

        private X509Name ReadName(ASN1Object asn1)
        {
            var result = new Dictionary<string, ASN1Object>();

            var rdnSeq = ToSeq(asn1, 1);

            foreach (var rdn in rdnSeq.Elements)
            {
                var rdnSet = ToSet(rdn, 1);
                foreach (var attr in rdnSet.Elements)
                {
                    var attrSeq = ToSeq(attr, 2, 2);

                    var type = GetElement<ASN1ObjectIdentifier>(attrSeq, 0);
                    var value = GetElement(attrSeq, 1);

                    result.Add(type.Identifier, value);
                }
            }

            return new X509Name(result);
        }

        private List<X509Extension> ReadExtensions(ASN1Sequence seq)
        {
            var extensions = new List<X509Extension>();

            foreach (var extInfo in seq.Elements)
            {
                var extSeq = ToSeq(extInfo, 2, 3);

                var id = GetElement<ASN1ObjectIdentifier>(extSeq, 0).Identifier;
                var critical = extSeq.Count == 3 && GetElement<ASN1Boolean>(extSeq, 1).Value;
                var value = GetElement<ASN1OctetString>(extSeq, extInfo.Count - 1).Value;
                ASN1Object asn1Value;
                using (var ms = new MemoryStream(value))
                {
                    asn1Value = new DERReader(ms).Read();
                }

                extensions.Add(new X509Extension(id, critical, asn1Value));
            }

            return extensions;
        }

        // helpers
        private ASN1Sequence ToSeq(ASN1Object asn1, int minLength = 0, int maxLength = int.MaxValue)
        {
            var seq = asn1 as ASN1Sequence;

            SecurityAssert.NotNull(seq);
            SecurityAssert.Assert(seq.Count >= minLength && seq.Count <= maxLength);

            return seq;
        }
        private ASN1Set ToSet(ASN1Object asn1, int minLength = 0, int maxLength = int.MaxValue)
        {
            var seq = asn1 as ASN1Set;

            SecurityAssert.NotNull(seq);
            SecurityAssert.Assert(seq.Count >= minLength && seq.Count <= maxLength);

            return seq;
        }

        private ASN1Object GetElement(ASN1Object asn1, int index)
        {
            SecurityAssert.Assert(index >= 0 && index < asn1.Count);

            return asn1.Elements[index];
        }
        private T GetElement<T>(ASN1Object asn1, int index)
            where T : ASN1Object
        {
            var obj = GetElement(asn1, index) as T;
            SecurityAssert.NotNull(obj);

            return obj;
        }
    }
}
