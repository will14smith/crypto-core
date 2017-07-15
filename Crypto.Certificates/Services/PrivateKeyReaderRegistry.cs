using Crypto.ASN1;
using Crypto.Certificates.Keys;
using Crypto.Core.Registry;

namespace Crypto.Certificates.Services
{
    public class PrivateKeyReaderRegistry : BaseRegistry<ASN1ObjectIdentifier, IPrivateKeyReader>
    {
    }
}