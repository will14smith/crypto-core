using System;
using Crypto.Core.Encryption.Parameters;
using Crypto.Utils;

namespace Crypto.Core.Encryption
{
    public class NullCipher : ICipher
    {
        public int KeySize => 0;

        public void Init(ICipherParameters parameters)
        {
        }

        public void Encrypt(ReadOnlySpan<byte> input, Span<byte> output)
        {
            SecurityAssert.AssertInputOutputBuffers(input, output);

            input.CopyTo(output);
        }

        public void Decrypt(ReadOnlySpan<byte> input, Span<byte> output)
        {
            SecurityAssert.AssertInputOutputBuffers(input, output);

            input.CopyTo(output);
        }
    }
}
