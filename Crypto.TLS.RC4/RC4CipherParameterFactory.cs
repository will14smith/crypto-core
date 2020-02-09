using System;
using Crypto.Core.Encryption.Parameters;
using Crypto.RC4;
using Crypto.TLS.Config;
using Crypto.TLS.Services;
using Crypto.TLS.Suites.Parameters;
using Crypto.Utils;

namespace Crypto.TLS.RC4
{
    public class RC4CipherParameterFactory : ICipherParameterFactory
    {
        private readonly KeyConfig _keyConfig;

        public RC4CipherParameterFactory(KeyConfig keyConfig)
        {
            _keyConfig = keyConfig;
        }

        public ICipherParameters Create(ConnectionEnd end, ConnectionDirection direction)
        {
            var key = GetKey(end, direction);

            SecurityAssert.NotNull(key);
            SecurityAssert.Assert(key.Length > 0);

            return new RC4KeyParameter(key);
        }

        private byte[] GetKey(ConnectionEnd end, ConnectionDirection direction)
        {
            switch (end)
            {
                case ConnectionEnd.Client:
                    switch (direction)
                    {
                        case ConnectionDirection.Read:
                            return _keyConfig.Server ?? throw new InvalidOperationException("Server key is not initialized");
                        case ConnectionDirection.Write:
                            return _keyConfig.Client ?? throw new InvalidOperationException("Client key is not initialized");
                        default:
                            throw new ArgumentOutOfRangeException(nameof(direction), direction, null);
                    }
                case ConnectionEnd.Server:
                    switch (direction)
                    {
                        case ConnectionDirection.Read:
                            return _keyConfig.Client ?? throw new InvalidOperationException("Client key is not initialized");
                        case ConnectionDirection.Write:
                            return _keyConfig.Server ?? throw new InvalidOperationException("Server key is not initialized");
                        default:
                            throw new ArgumentOutOfRangeException(nameof(direction), direction, null);
                    }
                default:
                    throw new ArgumentOutOfRangeException(nameof(end), end, null);
            }
        }
    }
}
