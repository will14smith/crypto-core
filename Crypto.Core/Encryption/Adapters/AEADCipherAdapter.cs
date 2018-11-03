using System;
using Crypto.Core.Encryption.Parameters;
using Crypto.Utils;

namespace Crypto.Core.Encryption.Adapters
{
    public class AEADCipherAdapter : ICipher
    {
        public IAEADBlockCipher Cipher { get; }

        public AEADCipherAdapter(IAEADBlockCipher cipher)
        {
            Cipher = cipher;
        }

        public int KeySize => Cipher.KeySize;
        public int BlockLength => Cipher.BlockLength;
        public int TagLength => Cipher.TagLength;

        public void Init(ICipherParameters parameters)
        {
            Cipher.Init(parameters);
        }

        public CipherResult Encrypt(ReadOnlySpan<byte> input, Span<byte> output)
        {
            SecurityAssert.AssertInputOutputBuffers(input, output, input.Length + TagLength);
            
            (input, output) = Cipher.EncryptFinal(Cipher.Encrypt(input, output));

            return new CipherResult(input, output);
        }

        public CipherResult Decrypt(ReadOnlySpan<byte> input, Span<byte> output)
        {
            SecurityAssert.AssertInputOutputBuffers(input, output, input.Length + TagLength);

            (input, output) = Cipher.DecryptFinal(Cipher.Decrypt(input, output));

            return new CipherResult(input, output);
        }
    }
}
