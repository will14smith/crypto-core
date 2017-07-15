using Crypto.Core.Encryption.Parameters;

namespace Crypto.Core.Encryption
{
    public interface IBlockCipher
    {
        int BlockLength { get; }
        int KeyLength { get; }

        void Init(ICipherParameters parameters);

        void EncryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset);
        void DecryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset);
    }
}