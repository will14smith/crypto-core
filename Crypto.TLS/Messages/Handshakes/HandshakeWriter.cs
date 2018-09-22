using Crypto.TLS.Config;
using Crypto.TLS.Records;

namespace Crypto.TLS.Messages.Handshakes
{
    public class HandshakeWriter
    {
        private readonly Connection _connection;
        
        private readonly VersionConfig _versionConfig;
        private readonly HandshakeConfig _handshakeConfig;

        public HandshakeWriter(
            Connection connection,
            
            VersionConfig versionConfig,
            HandshakeConfig handshakeConfig)
        {
            _connection = connection;
            
            _versionConfig = versionConfig;
            _handshakeConfig = handshakeConfig;
        }

        public void Write(HandshakeMessage message)
        {
            var body = message.GetBytes();
            var record = new Record(RecordType.Handshake, _versionConfig.Version, body);

            _handshakeConfig.UpdateVerification(body);
            _connection.WriteRecord(record);
        }
    }
}
