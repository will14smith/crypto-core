using System.Collections.Generic;
using System.IO;
using System.Linq;
using Crypto.ASN1;

namespace Crypto.Certificates
{
    public class X509Writer
    {
        private readonly Stream _stream;

        public X509Writer(Stream stream)
        {
            _stream = stream;
        }

        public void WriteCertificate(X509Certificate cert)
        {
            // build ASN1
            var asn1 = GetASN1(cert);

            // write ASN1 to stream
            new DERWriter(_stream).Write(asn1);
        }

        private ASN1Object GetASN1(X509Certificate cert)
        {
            var taggedVersion = cert.Version.HasValue ? new ASN1Tagged(0, new[] {new ASN1Integer(cert.Version.Value - 1)}) : null;
            var serialNumber = new ASN1Integer(cert.SerialNumber);
            var signatureAlgo = GetAlgorithmIdentifier(cert.SignatureAlgorithm);
            var issuer = GetName(cert.Issuer);
            var validity = GetValidity(cert.Validity);
            var subject = GetName(cert.Subject);
            var subjectPublicKeyInfo = new ASN1Sequence(new[]
            {
                GetAlgorithmIdentifier(cert.SubjectPublicKeyAlgorithm),
                new ASN1BitString(cert.SubjectPublicKey.GetBytes())
            });

            var tbs = new List<ASN1Object>();
            if (taggedVersion != null)
            {
                tbs.Add(taggedVersion);
            }

            tbs.Add(serialNumber);
            tbs.Add(signatureAlgo);
            tbs.Add(issuer);
            tbs.Add(validity);
            tbs.Add(subject);
            tbs.Add(subjectPublicKeyInfo);

            if (cert.Version >= 2)
            {
                //TODO issuerUniqueID  
                //TODO subjectUniqueID 
            }

            if (cert.Version >= 3)
            {
                var extensions = GetExtensions(cert.Extensions);
                var taggedExtensions = new ASN1Tagged(3, new[] { extensions });
                tbs.Add(taggedExtensions);
            }

            return new ASN1Sequence(new List<ASN1Object>
            {
                new ASN1Sequence(tbs),
                signatureAlgo,
                new ASN1BitString(cert.Signature)
            });
        }

        private static ASN1Object GetAlgorithmIdentifier(X509AlgorithmIdentifier algorithm)
        {
            return new ASN1Sequence(new[] { algorithm.Algorithm }.Concat(algorithm.Parameters));
        }

        private static ASN1Object GetName(X509Name name)
        {
            ASN1Sequence AttrToRdn(KeyValuePair<string, ASN1Object> attr) => new ASN1Sequence(new[] {new ASN1ObjectIdentifier(attr.Key), attr.Value});

            var rdns =
                name.Values.GroupBy(x => x.Key)
                    .Select(attrs => new ASN1Set(attrs.Select(AttrToRdn)))
                    .Cast<ASN1Object>().ToList();

            return new ASN1Sequence(rdns);
        }

        private static ASN1Object GetValidity(X509Validity validity)
        {
            return new ASN1Sequence(new[]
            {
                new ASN1UTCTime(validity.NotBefore),
                new ASN1UTCTime(validity.NotAfter),
            });
        }

        private static ASN1Object GetExtensions(IEnumerable<X509Extension> extensions)
        {
            var extsSeq = new List<ASN1Object>();

            foreach (var extension in extensions)
            {
                var extSeq = new List<ASN1Object>
                {
                    new ASN1ObjectIdentifier(extension.Id)
                };

                if (extension.Critical)
                {
                    extSeq.Add(new ASN1Boolean(true));
                }

                using (var ms = new MemoryStream())
                {
                    new DERWriter(ms).Write(extension.Value);
                    extSeq.Add(new ASN1OctetString(ms.ToArray()));
                }

                extsSeq.Add(new ASN1Sequence(extSeq));
            }

            return new ASN1Sequence(extsSeq);
        }
    }
}
