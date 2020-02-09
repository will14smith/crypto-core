using System;
using Crypto.Core.Encryption.Parameters;
using Crypto.Utils;

namespace Crypto.Core.Encryption.BlockModes
{
    public abstract class IVBlockCipher : IBlockCipher
    {
        public IBlockCipher Cipher { get; }

        protected bool IVInitialised { get; private set; }
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
            if (!(parameters is IVParameter ivParams))
            {
                Cipher.Init(parameters);
                return;
            }

            var ivParam = ivParams.IV;
            SecurityAssert.NotNull(ivParam);
            SecurityAssert.Assert(ivParam.Length == BlockLength);

            Array.Copy(ivParam, IV, BlockLength);
            IVInitialised = true;

            if (ivParams.HasParameters)
            {
                Cipher.Init(ivParams.Parameters);
            }

            Reset();
        }

        protected abstract void Reset();

        public abstract void EncryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset);
        public abstract void DecryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset);
    }
}
