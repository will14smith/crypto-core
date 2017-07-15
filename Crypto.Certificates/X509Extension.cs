using Crypto.ASN1;

namespace Crypto.Certificates
{
    public class X509Extension
    {
        public string Id { get; }
        public bool Critical { get; }
        public ASN1Object Value { get; }

        public X509Extension(string id, bool critical, ASN1Object value)
        {
            Id = id;
            Critical = critical;
            Value = value;
        }
    }
}