using Crypto.Certificates.Keys;
using Crypto.Core.Encryption.Parameters;

namespace Crypto.Certificates.Parameters
{
    public class PublicKeyParameter : ICipherParameters
    {
        public PublicKeyParameter(PublicKey key)
        {
            Key = key;
        }

        public PublicKey Key { get; }
    }
}