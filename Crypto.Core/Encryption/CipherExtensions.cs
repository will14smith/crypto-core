namespace Crypto.Core.Encryption
{
    public static class CipherExtensions
    {
        public static CipherResult Encrypt(this ICipher cipher, CipherResult previousResult)
        {
            return cipher.Encrypt(previousResult.RemainingInput, previousResult.RemainingOutput);
        }

        public static CipherResult Decrypt(this ICipher cipher, CipherResult previousResult)
        {
            return cipher.Decrypt(previousResult.RemainingInput, previousResult.RemainingOutput);
        }
    }
}