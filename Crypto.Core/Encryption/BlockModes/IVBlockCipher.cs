using System;
using Crypto.Core.Encryption.Parameters;
using Crypto.Utils;

namespace Crypto.Core.Encryption.BlockModes
{
    public abstract class IVBlockCipher : IBlockCipher
    {
        public IBlockCipher Cipher { get; }

        protected bool IVInitialized { get; private set; }
        protected byte[] IV { get; }

        protected IVBlockCipher(IBlockCipher cipher)
        {
            Cipher = cipher;

            IV = new byte[BlockLength];
        }

        public int BlockLength => Cipher.BlockLength;
        public int KeySize => Cipher.KeySize;

        public virtual void Init(ICipherParameters parameters)
        {
            var ivParams = parameters as IVParameter;
            if (ivParams == null)
            {
                Cipher.Init(parameters);
                return;
            }

            var ivParam = ivParams.IV;
            SecurityAssert.NotNull(ivParam);
            SecurityAssert.Assert(ivParam.Length == BlockLength);
            ivParam.Span.CopyTo(IV);

            IVInitialized = true;

            if (ivParams.Parameters != null)
            {
                Cipher.Init(ivParams.Parameters);
            }

            Reset();
        }

        protected abstract void Reset();

        public abstract BlockResult EncryptBlock(ReadOnlySpan<byte> input, Span<byte> output);
        public abstract BlockResult DecryptBlock(ReadOnlySpan<byte> input, Span<byte> output);
    }
}
