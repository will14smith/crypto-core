using Crypto.Core.Encryption.Parameters;

namespace Crypto.Core.Encryption
{
    public interface ICipher
    {
        int KeySize { get; }

        void Init(ICipherParameters parameters);

        void Encrypt(byte[] input, int inputOffset, byte[] output, int outputOffset, int length);
        void Decrypt(byte[] input, int inputOffset, byte[] output, int outputOffset, int length);
    }
}
