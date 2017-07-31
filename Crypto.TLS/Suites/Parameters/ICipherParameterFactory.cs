using Crypto.Core.Encryption.Parameters;

namespace Crypto.TLS.Suites.Parameters
{
    public interface ICipherParameterFactory
    {
        ICipherParameters Create(ConnectionEnd end, ConnectionDirection direction);
    }
}
