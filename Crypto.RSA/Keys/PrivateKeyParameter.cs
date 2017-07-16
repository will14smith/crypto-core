using Crypto.Core.Encryption.Parameters;

namespace Crypto.RSA.Keys
{
    public class RSAPrivateKeyParameter : ICipherParameters
    {
        public RSAPrivateKeyParameter(RSAPrivateKey key)
        {
            Key = key;
        }

        public RSAPrivateKey Key { get; }
    }
}