namespace Crypto.Core.Encryption.Parameters
{
    public class IVParameter : ICipherParameters
    {
        public IVParameter(byte[] iv) : this(new NullCipherParameter(), iv) { }     
        public IVParameter(ICipherParameters parameters, byte[] iv)
        {
            IV = iv;
            Parameters = parameters;
        }

        public byte[] IV { get; }

        public bool HasParameters => Parameters != null && !(Parameters is NullCipherParameter);
        public ICipherParameters Parameters { get; }
    }
}