using System;

namespace Crypto.Core.Encryption
{
    public static class AEADBlockCipherExtensions
    {
        public static AEADResult Encrypt(this IAEADBlockCipher cipher, AEADResult previousResult)
        {
            return cipher.Encrypt(previousResult.RemainingInput, previousResult.RemainingOutput);
        }

        public static AEADResult Decrypt(this IAEADBlockCipher cipher, AEADResult previousResult)
        {
            return cipher.Decrypt(previousResult.RemainingInput, previousResult.RemainingOutput);
        }

        public static AEADResult EncryptAll(this IAEADBlockCipher cipher, ReadOnlySpan<byte> input, Span<byte> output)
        {
            return cipher.EncryptFinal(cipher.Encrypt(input, output));
        }

        public static AEADResult DecryptAll(this IAEADBlockCipher cipher, ReadOnlySpan<byte> input, Span<byte> output)
        {
            return cipher.DecryptFinal(cipher.Decrypt(input, output));
        }
    }
}