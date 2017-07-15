using Crypto.Core.Encryption.Parameters;
using Crypto.Utils;

namespace Crypto.Core.Encryption.Adapters
{
    public class BlockCipherAdapter : ICipher
    {
        public IBlockCipher BlockCipher { get; }

        public BlockCipherAdapter(IBlockCipher blockCipher)
        {
            BlockCipher = blockCipher;
        }

        public int KeySize => BlockCipher.KeyLength;
        public int BlockLength => BlockCipher.BlockLength;

        public void Init(ICipherParameters parameters)
        {
            BlockCipher.Init(parameters);
        }

        public void Encrypt(byte[] input, int inputOffset, byte[] output, int outputOffset, int length)
        {
            SecurityAssert.AssertBuffer(input, inputOffset, length);
            SecurityAssert.AssertBuffer(output, outputOffset, length);

            for (var i = 0; i < length; i += BlockCipher.BlockLength)
            {
                BlockCipher.EncryptBlock(input, inputOffset + i, output, outputOffset + i);
            }
        }

        public void Decrypt(byte[] input, int inputOffset, byte[] output, int outputOffset, int length)
        {
            SecurityAssert.AssertBuffer(input, inputOffset, length);
            SecurityAssert.AssertBuffer(output, outputOffset, length);

            for (var i = 0; i < length; i += BlockCipher.BlockLength)
            {
                BlockCipher.DecryptBlock(input, inputOffset + i, output, outputOffset + i);
            }
        }
    }
}
