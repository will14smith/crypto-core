using Crypto.Core.Encryption.Parameters;
using Crypto.Core.Hashing;

namespace Crypto.Core.Signing
{
    public interface ISignatureCipher
    {
        void Init(ICipherParameters parameters);

        byte[] Sign(byte[] input, IDigest hash);
        bool Verify(byte[] input, byte[] signature, IDigest hash);
    }
}
