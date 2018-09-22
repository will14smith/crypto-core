using System;

namespace Crypto.Core.Encryption.Parameters
{
    public class AADParameter : ICipherParameters
    {
        public AADParameter(ICipherParameters parameters, ReadOnlySpan<byte> aad)
        {
            Parameters = parameters;
            AAD = aad.ToArray();
        }

        public ReadOnlyMemory<byte> AAD { get; }
        public ICipherParameters Parameters { get; }
    }
}
