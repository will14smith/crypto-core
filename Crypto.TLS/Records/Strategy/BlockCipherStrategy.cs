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

            cipher.Decrypt(payload, plaintext);

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

            var content = plaintext.AsMemory(0, contentLength);
            var mac = plaintext.AsSpan(contentLength, macLength);

            var seqNum = _sequenceConfig.GetThenIncrement(ConnectionDirection.Read);
            var computedMac = ComputeMAC(macAlgo, seqNum, type, version, content.Span);

            SecurityAssert.AssertHash(mac, computedMac);

            return new Record(type, version, content);
        }

        public void Write(RecordType type, TLSVersion version, ReadOnlySpan<byte> data)
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

            data.CopyTo(plaintext.AsSpan(offset));
            offset += data.Length;

            mac.CopyTo(plaintext.AsSpan(offset));
            offset += mac.Length;

            for (; offset < payloadLength; offset++)
            {
                plaintext[offset] = padding;
            }

            cipher.Init(new IVParameter(GetParameters(ConnectionDirection.Write), iv));
            cipher.Encrypt(plaintext, payload);

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

            SecurityAssert.Assert(key.Length > 0);

            return new HMAC(digest, key);
        }

        private ReadOnlySpan<byte> GetMACKey(ConnectionDirection direction)
        {
            switch (_endConfig.End)
            {
                case ConnectionEnd.Client:
                    switch (direction)
                    {
                        case ConnectionDirection.Read:
                            return _blockCipherConfig.ServerMACKey.Span;
                        case ConnectionDirection.Write:
                            return _blockCipherConfig.ClientMACKey.Span;
                        default:
                            throw new ArgumentOutOfRangeException(nameof(direction), direction, null);
                    }
                case ConnectionEnd.Server:
                    switch (direction)
                    {
                        case ConnectionDirection.Read:
                            return _blockCipherConfig.ClientMACKey.Span;
                        case ConnectionDirection.Write:
                            return _blockCipherConfig.ServerMACKey.Span;
                        default:
                            throw new ArgumentOutOfRangeException(nameof(direction), direction, null);
                    }
                default:
                    throw new ArgumentOutOfRangeException(nameof(_endConfig.End), _endConfig.End, null);
            }
        }

        private ReadOnlySpan<byte> ComputeMAC(IDigest macAlgo, long seqNum, RecordType type, TLSVersion version, ReadOnlySpan<byte> content)
        {
            macAlgo.Update(EndianBitConverter.Big.GetBytes(seqNum));
            macAlgo.Update(new[] { (byte)type, version.Major, version.Major });
            macAlgo.Update(EndianBitConverter.Big.GetBytes((ushort)content.Length));
            macAlgo.Update(content);

            return macAlgo.Digest();
        }
    }
}
