using System.Collections.Generic;
using Crypto.Certificates;

namespace Crypto.TLS.Config
{
    public class CertificateConfig
    {
        public IReadOnlyList<X509Certificate>? CertificateChain { get; set; }
        public X509Certificate? Certificate => CertificateChain?[0];
    }
}
