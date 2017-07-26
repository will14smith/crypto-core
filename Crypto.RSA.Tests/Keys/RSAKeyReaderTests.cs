using System;
using System.Collections;
using System.IO;
using System.Numerics;
using Crypto.ASN1;
using Crypto.Certificates;
using Crypto.RSA.Keys;
using Xunit;

namespace Crypto.RSA.Tests.Keys
{
    public class RSAKeyReaderTests
    {
        [Fact]
        public void ReadPublicKey_CorrectlyReads()
        {
            var sha256WithRSA = new ASN1ObjectIdentifier("1.2.840.113549.1.1.11");
            var keyAlgorithm = new X509AlgorithmIdentifier(sha256WithRSA, new ASN1Object[] { new ASN1Null() });

            BitArray keyData;
            using (var ms = new MemoryStream())
            {
                var writer = new DERWriter(ms);

                writer.Write(new ASN1Sequence(new ASN1Object[]
                {
                    new ASN1Integer(123),
                    new ASN1Integer(456)
                }));

                keyData = new BitArray(ms.ToArray());
            }

            var key = new RSAKeyReader().ReadPublicKey(keyAlgorithm, keyData);

            var rsaKey = Assert.IsType<RSAPublicKey>(key);
            Assert.Equal(123, rsaKey.Modulus);
            Assert.Equal(456, rsaKey.Exponent);
        }

        [Fact]
        public void ReadPrivateKey_CorrectlyReads()
        {
            var keyData = Convert.FromBase64String(@"MGMCAQACEQC22aTrdWZfC+U35KxlhaNrAgMBAAECEAjmcyaa4k7B+mPPmFvm3QECCQDhYc7boBK6wQIJAM+wsIZ/2oUrAgkAxCFASQFAq0ECCQCDdjjWedlMzwIIT7KUwpmsGjE=");

            var modulus = BigInteger.Parse("243049568621283441616897908737715839851");
            var privateExponent = BigInteger.Parse("11830387779451213492505862747361565953");
            var publicExponent = BigInteger.Parse("65537");
            
            var sha256WithRSA = new ASN1ObjectIdentifier("1.2.840.113549.1.1.11");
            var keyAlgorithm = new X509AlgorithmIdentifier(sha256WithRSA, new ASN1Object[] { new ASN1Null() });

            var key = new RSAKeyReader().ReadPrivateKey(keyAlgorithm, keyData);

            var rsaKey = Assert.IsType<RSAPrivateKey>(key);
            Assert.Equal(modulus, rsaKey.Modulus);
            Assert.Equal(privateExponent, rsaKey.Exponent);

            var rsaPublicKey = Assert.IsType<RSAPublicKey>(key.PublicKey);
            Assert.Equal(modulus, rsaPublicKey.Modulus);
            Assert.Equal(publicExponent, rsaPublicKey.Exponent);
        }
    }
}
