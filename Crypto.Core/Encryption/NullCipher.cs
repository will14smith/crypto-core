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

        public CipherResult Encrypt(ReadOnlySpan<byte> input, Span<byte> output)
        {
            SecurityAssert.AssertInputOutputBuffers(input, output);

            input.CopyTo(output);

            return new CipherResult(new ReadOnlySpan<byte>(), output.Slice(input.Length));
        }

        public CipherResult Decrypt(ReadOnlySpan<byte> input, Span<byte> output)
        {
            SecurityAssert.AssertInputOutputBuffers(input, output);

            input.CopyTo(output);

            return new CipherResult(new ReadOnlySpan<byte>(), output.Slice(input.Length));
        }
    }
}
