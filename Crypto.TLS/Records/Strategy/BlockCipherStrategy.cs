using System;
using Crypto.Core.Encryption;
using Crypto.Core.Encryption.Adapters;
using Crypto.Core.Encryption.Parameters;
using Crypto.Core.Hashing;
using Crypto.Core.Randomness;
using Crypto.TLS.Config;
using Crypto.TLS.Suites.Providers;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.TLS.Records.Strategy
{
    public class BlockCipherStrategy : IRecordReaderStrategy, IRecordWriterStrategy
    {
        private readonly IRandom _random;
        private readonly ICipherSuitesProvider _cipherSuitesProvider;

        private readonly Connection _connection;

        private readonly EndConfig _endConfig;
        private readonly SequenceConfig _sequenceConfig;
        private readonly CipherSuiteConfig _cipherSuiteConfig;
        private readonly BlockCipherConfig _blockCipherConfig;

        public BlockCipherStrategy(
            IRandom random,
            ICipherSuitesProvider cipherSuitesProvider,

            Connection connection,

            EndConfig endConfig,
            SequenceConfig sequenceConfig,
            BlockCipherConfig blockCipherConfig,
            CipherSuiteConfig cipherSuiteConfig)
        {
            _random = random;
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

            var blockLength = cipher.BlockLength;
            var iv = _connection.Reader.ReadBytes(blockLength);

            cipher.Init(new IVParameter(GetParameters(ConnectionDirection.Read), iv));

            var payload = _connection.Reader.ReadBytes(length - blockLength);
            var plaintext = new byte[payload.Length];

            cipher.Decrypt(payload, 0, plaintext, 0, payload.Length);

            var macAlgo = GetMAC(ConnectionDirection.Read);
            var macLength = macAlgo.HashSize / 8;
            var paddingLength = plaintext[plaintext.Length - 1];
            var contentLength = plaintext.Length - paddingLength - macLength - 1;
            SecurityAssert.Assert(contentLength >= 0);

            //TODO constant time
            for (var i = plaintext.Length - 1; i > plaintext.Length - paddingLength; i--)
            {
                SecurityAssert.Assert(plaintext[i] == paddingLength);
            }

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

            var iv = _random.RandomBytes(cipher.BlockLength);

            var payloadLength = data.Length + macAlgo.HashSize / 8;

            var padding = (byte)(cipher.BlockLength - 1 - payloadLength % cipher.BlockLength);
            // TODO padding can be upto 255, so possible add more than the minimum

            payloadLength += padding + 1;

            var plaintext = new byte[payloadLength];
            var payload = new byte[payloadLength];

            var offset = 0;

            Array.Copy(data, 0, plaintext, offset, data.Length);
            offset += data.Length;

            Array.Copy(mac, 0, plaintext, offset, mac.Length);
            offset += mac.Length;

            for (; offset < payloadLength; offset++)
            {
                plaintext[offset] = padding;
            }

            cipher.Init(new IVParameter(GetParameters(ConnectionDirection.Write), iv));
            cipher.Encrypt(plaintext, 0, payload, 0, plaintext.Length);

            _connection.Writer.Write(type);
            _connection.Writer.Write(version);
            _connection.Writer.Write((ushort)(iv.Length + payloadLength));
            _connection.Writer.Write(iv);
            _connection.Writer.Write(payload);
        }

        private BlockCipherAdapter GetCipher()
        {
            var cipher = _cipherSuitesProvider.ResolveCipherAlgorithm(_cipherSuiteConfig.CipherSuite);

            if (cipher is BlockCipherAdapter adapter)
            {
                return adapter;
            }

            if (cipher is IBlockCipher blockCipher)
            {
                return new BlockCipherAdapter(blockCipher);
            }

            throw new InvalidCastException("Cipher isn't a block cipher");
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
            if (_blockCipherConfig.ClientMACKey is null || _blockCipherConfig.ServerMACKey is null)
            {
                
            }
            
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

            return macAlgo.DigestBuffer();
        }
    }
}
