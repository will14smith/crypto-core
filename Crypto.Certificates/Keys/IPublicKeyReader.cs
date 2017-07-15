using System.Collections;

namespace Crypto.Certificates.Keys
{
    public interface IPublicKeyReader
    {
        PublicKey ReadPublicKey(X509AlgorithmIdentifier algorithm, BitArray bits);
    }
}
