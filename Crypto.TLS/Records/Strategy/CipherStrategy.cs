using System;
using Crypto.Core.Encryption;
using Crypto.Core.Encryption.Parameters;
using Crypto.Core.Hashing;
using Crypto.TLS.Config;
using Crypto.TLS.Suites.Providers;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.TLS.Records.Strategy
{
    public class CipherStrategy : IRecordReaderStrategy, IRecordWriterStrategy
    {
        private readonly ICipherSuitesProvider _cipherSuitesProvider;
        
        private readonly Connection _connection;

        private readonly EndConfig _endConfig;
        private readonly SequenceConfig _sequenceConfig;
        private readonly BlockCipherConfig _blockCipherConfig;
        private readonly CipherSuiteConfig _cipherSuiteConfig;

        public CipherStrategy(
            ICipherSuitesProvider cipherSuitesProvider,

            Connection connection,

            EndConfig endConfig,
            SequenceConfig sequenceConfig,
            BlockCipherConfig blockCipherConfig,
            CipherSuiteConfig cipherSuiteConfig)
        {
            _cipherSuitesProvider = cipherSuitesProvider;
            
            _connection = connection;

            _endConfig = endConfig;
            _sequenceConfig = sequenceConfig;
            _blockCipherConfig = blockCipherConfig;
            _cipherSuiteConfig = cipherSuiteConfig;
        }

        public Record Read(RecordType type, TLSVersion version, ushort length)
        {
            var cipher = GetCipher();
            cipher.Init(GetParameters(ConnectionDirection.Read));

            var payload = _connection.Reader.ReadBytes(length);
            var plaintext = new byte[payload.Length];

            cipher.Decrypt(payload, 0, plaintext, 0, payload.Length);

            var macAlgo = GetMAC(ConnectionDirection.Read);
            var macLength = macAlgo.HashSize / 8;
            var contentLength = plaintext.Length - macLength;
            SecurityAssert.Assert(contentLength >= 0);

            var mac = new byte[macLength];
            Array.Copy(plaintext, contentLength, mac, 0, macLength);

            var content = new byte[contentLength];
            Array.Copy(plaintext, 0, content, 0, content.Length);

            var seqNum = _sequenceConfig.GetThenIncrement(ConnectionDirection.Read);
            var computedMac = ComputeMAC(macAlgo, seqNum, type, version, content);

            SecurityAssert.AssertHash(mac, computedMac);

            return new Record(type, version, content);
        }

        public void Write(RecordType type, TLSVersion version, byte[] data)
        {
            var cipher = GetCipher();

            var macAlgo = GetMAC(ConnectionDirection.Write);
            var seqNum = _sequenceConfig.GetThenIncrement(ConnectionDirection.Write);
            var mac = ComputeMAC(macAlgo, seqNum, type, version, data);

            var payloadLength = data.Length + macAlgo.HashSize / 8;

            var plaintext = new byte[payloadLength];
            var payload = new byte[payloadLength];

            var offset = 0;

            Array.Copy(data, 0, plaintext, offset, data.Length);
            offset += data.Length;

            Array.Copy(mac, 0, plaintext, offset, mac.Length);
            offset += mac.Length;

            cipher.Init(GetParameters(ConnectionDirection.Write));
            cipher.Encrypt(plaintext, 0, payload, 0, plaintext.Length);

            _connection.Writer.Write(type);
            _connection.Writer.Write(version);
            _connection.Writer.Write(payload);
        }

        private ICipher GetCipher()
        {
            return _cipherSuitesProvider.ResolveCipherAlgorithm(_cipherSuiteConfig.CipherSuite);
        }
        
        private ICipherParameters GetParameters(ConnectionDirection direction)
        {
            var end = _endConfig.End;
            var cipherParameterFactory = _cipherSuitesProvider.ResolveCipherParameterFactory(_cipherSuiteConfig.CipherSuite);
            return cipherParameterFactory.Create(end, direction);
        }

        private IDigest GetMAC(ConnectionDirection direction)
        {
            var digest = _cipherSuitesProvider.ResolveHashAlgorithm(_cipherSuiteConfig.CipherSuite);

            var key = GetMACKey(direction);

            SecurityAssert.NotNull(key);
            SecurityAssert.Assert(key.Length > 0);

            return new HMAC(digest, key);
        }

        private byte[] GetMACKey(ConnectionDirection direction)
        {
            switch (_endConfig.End)
            {
                case ConnectionEnd.Client:
                    switch (direction)
                    {
                        case ConnectionDirection.Read:
                            return _blockCipherConfig.ServerMACKey ?? throw new InvalidOperationException("Server MAC key is not initialized");;
                        case ConnectionDirection.Write:
                            return _blockCipherConfig.ClientMACKey ?? throw new InvalidOperationException("Client MAC key is not initialized");;
                        default:
                            throw new ArgumentOutOfRangeException(nameof(direction), direction, null);
                    }
                case ConnectionEnd.Server:
                    switch (direction)
                    {
                        case ConnectionDirection.Read:
                            return _blockCipherConfig.ClientMACKey ?? throw new InvalidOperationException("Client MAC key is not initialized");;
                        case ConnectionDirection.Write:
                            return _blockCipherConfig.ServerMACKey ?? throw new InvalidOperationException("Server MAC key is not initialized");;
                        default:
                            throw new ArgumentOutOfRangeException(nameof(direction), direction, null);
                    }
                default:
                    throw new ArgumentOutOfRangeException(nameof(_endConfig.End), _endConfig.End, null);
            }
        }

        private byte[] ComputeMAC(IDigest macAlgo, long seqNum, RecordType type, TLSVersion version, byte[] content)
        {
            macAlgo.Update(EndianBitConverter.Big.GetBytes(seqNum), 0, sizeof(long));
            macAlgo.Update(new[] { (byte)type, version.Major, version.Major }, 0, 3);
            macAlgo.Update(EndianBitConverter.Big.GetBytes((ushort)content.Length), 0, sizeof(ushort));
            macAlgo.Update(content, 0, content.Length);

            return macAlgo.Digest();
        }
    }
}