using Crypto.ASN1;
using Crypto.Certificates.Keys;
using Crypto.Core.Registry;

namespace Crypto.Certificates.Services
{
    public class PublicKeyReaderRegistry : BaseRegistry<ASN1ObjectIdentifier, IPublicKeyReader>
    {
    }
}
