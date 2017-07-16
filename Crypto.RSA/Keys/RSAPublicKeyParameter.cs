using Crypto.Core.Encryption.Parameters;

namespace Crypto.RSA.Keys
{
    public class RSAPublicKeyParameter : ICipherParameters
    {
        public RSAPublicKeyParameter(RSAPublicKey key)
        {
            Key = key;
        }

        public RSAPublicKey Key { get; }
    }
}