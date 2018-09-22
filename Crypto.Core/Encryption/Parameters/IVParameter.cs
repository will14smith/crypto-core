using System;

namespace Crypto.Core.Encryption.Parameters
{
    public class IVParameter : ICipherParameters
    {
        public IVParameter(ICipherParameters parameters, ReadOnlySpan<byte> iv)
        {
            IV = iv.ToArray();
            Parameters = parameters;
        }

        public ReadOnlyMemory<byte> IV { get; }
        public ICipherParameters Parameters { get; }
    }
}