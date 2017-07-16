using Crypto.Core.Encryption.Parameters;
using Crypto.TLS.Services;

namespace Crypto.TLS.EC
{
    public class ECDSACipherParameterFactory : ICipherParameterFactory
    {
        public ICipherParameters Create(ConnectionEnd end, ConnectionDirection direction)
        {
            throw new System.NotImplementedException();
        }
    }
}