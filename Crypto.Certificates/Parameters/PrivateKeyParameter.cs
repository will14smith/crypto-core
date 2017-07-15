using Crypto.Certificates.Keys;
using Crypto.Core.Encryption.Parameters;

namespace Crypto.Certificates.Parameters
{
    public class PrivateKeyParameter : ICipherParameters
    {
        public PrivateKeyParameter(PrivateKey key)
        {
            Key = key;
        }

        public PrivateKey Key { get; }
    }
}