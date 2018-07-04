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

        public void Encrypt(ReadOnlySpan<byte> input, Span<byte> output)
        {
            SecurityAssert.AssertInputOutputBuffers(input, output, input.Length + TagLength);

            var tag = new byte[TagLength];
            
            var offset = Cipher.Encrypt(input, output);
            offset += Cipher.EncryptFinal(output.Slice(offset), tag);
            tag.CopyTo(output.Slice(offset));
        }

        public void Decrypt(ReadOnlySpan<byte> input, Span<byte> output)
        {
            SecurityAssert.AssertInputOutputBuffers(input, output, input.Length + TagLength);

            var offset = Cipher.Decrypt(input, output);
            Cipher.DecryptFinal(input.Slice(offset), output.Slice(offset));
        }
    }
}
