using Crypto.Core.Encryption.Parameters;

namespace Crypto.TLS.Services
{
    public interface ICipherParameterFactory
    {
        ICipherParameters Create(ConnectionEnd end, ConnectionDirection direction);
    }
}
