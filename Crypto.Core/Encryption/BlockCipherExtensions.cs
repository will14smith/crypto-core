using System;

namespace Crypto.Core.Encryption
{
    public static class BlockCipherExtensions
    {
        public static BlockResult EncryptBlock(this IBlockCipher cipher, BlockResult previousResult)
        {
            return cipher.EncryptBlock(previousResult.RemainingInput, previousResult.RemainingOutput);
        }

        public static BlockResult DecryptBlock(this IBlockCipher cipher, BlockResult previousResult)
        {
            return cipher.DecryptBlock(previousResult.RemainingInput, previousResult.RemainingOutput);
        }
    }
}
