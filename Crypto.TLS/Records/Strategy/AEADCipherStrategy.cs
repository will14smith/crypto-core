﻿using System;
using Crypto.Core.Encryption;
using Crypto.Core.Encryption.Adapters;
using Crypto.Core.Encryption.Parameters;
using Crypto.Core.Randomness;
using Crypto.TLS.Config;
using Crypto.TLS.Suites.Providers;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.TLS.Records.Strategy
{
    public class AEADCipherStrategy : IRecordReaderStrategy, IRecordWriterStrategy
    {
        private readonly IRandom _random;
        private readonly ICipherSuitesProvider _cipherSuitesProvider;

        private readonly Connection _connection;

        private readonly CipherSuiteConfig _cipherSuiteConfig;
        private readonly SequenceConfig _sequenceConfig;
        private readonly EndConfig _endConfig;
        private readonly AEADCipherConfig _aeadConfig;

        public AEADCipherStrategy(
            IRandom random,
            ICipherSuitesProvider cipherSuitesProvider,

            Connection connection,

            CipherSuiteConfig cipherSuiteConfig,
            SequenceConfig sequenceConfig,
            EndConfig endConfig,
            AEADCipherConfig aeadConfig)
        {
            _random = random;
            _cipherSuitesProvider = cipherSuitesProvider;

            _connection = connection;

            _cipherSuiteConfig = cipherSuiteConfig;
            _sequenceConfig = sequenceConfig;
            _endConfig = endConfig;
            _aeadConfig = aeadConfig;
        }

        public Record Read(RecordType type, TLSVersion version, ushort length)
        {
            var cipher = GetCipher();

            // TODO parametrised from CipherSpec
            var explicitNonceLength = 8;

            var nonce = _connection.Reader.ReadBytes(explicitNonceLength);
            var payload = _connection.Reader.ReadBytes(length - explicitNonceLength);

            var aad = new byte[13];
            Array.Copy(EndianBitConverter.Big.GetBytes(_sequenceConfig.GetThenIncrement(ConnectionDirection.Read)), 0, aad, 0, 8);
            Array.Copy(new[] { (byte)type, version.Major, version.Major }, 0, aad, 8, 3);
            Array.Copy(EndianBitConverter.Big.GetBytes((ushort)(length - explicitNonceLength - cipher.TagLength)), 0, aad, 11, 2);

            cipher.Init(GetParameters(ConnectionDirection.Read, aad, nonce));

            var plaintext = new byte[payload.Length - cipher.TagLength];

            var input = payload.AsSpan();
            var output = plaintext.AsSpan();
            
            var result = cipher.DecryptAll(input, output);

            Array.Resize(ref plaintext, plaintext.Length - result.RemainingOutput.Length);

            return new Record(type, version, plaintext);
        }

        public void Write(RecordType type, TLSVersion version, byte[] data)
        {
            var cipher = GetCipher();

            // TODO parametrised from CipherSpec
            var explicitNonceLength = 8;
            var nonce = _random.RandomBytes(explicitNonceLength);

            var aad = new byte[13];
            Array.Copy(EndianBitConverter.Big.GetBytes(_sequenceConfig.GetThenIncrement(ConnectionDirection.Write)), 0, aad, 0, 8);
            Array.Copy(new[] { (byte)type, version.Major, version.Major }, 0, aad, 8, 3);
            Array.Copy(EndianBitConverter.Big.GetBytes((ushort)data.Length), 0, aad, 11, 2);

            var payload = new byte[explicitNonceLength + data.Length + cipher.TagLength];
            Array.Copy(nonce, payload, explicitNonceLength);

            cipher.Init(GetParameters(ConnectionDirection.Write, aad, nonce));

            var input = data.AsSpan();
            var output = payload.AsSpan(explicitNonceLength);
            
            var result = cipher.EncryptAll(input, output);
            var payloadLength = payload.Length - result.RemainingOutput.Length;

 
            
            _connection.Writer.Write(type);
            _connection.Writer.Write(version);
            _connection.Writer.Write((ushort)payloadLength);
            _connection.Writer.Write(payload, 0, payloadLength);
        }

        private IAEADBlockCipher GetCipher()
        {
            var cipher = _cipherSuitesProvider.ResolveCipherAlgorithm(_cipherSuiteConfig.CipherSuite);

            if (cipher is AEADCipherAdapter adapter)
            {
                return adapter.Cipher;
            }

            // ReSharper disable SuspiciousTypeConversion.Global
            if (cipher is IAEADBlockCipher aeadCipher)
            {
                return aeadCipher;
            }
            // ReSharper enable SuspiciousTypeConversion.Global

            throw new InvalidCastException("Cipher isn't an AEAD cipher");
        }

        private ICipherParameters GetParameters(ConnectionDirection direction, byte[] aad, byte[] nonceExplicit)
        {
            var end = _endConfig.End;
            var cipherParameterFactory = _cipherSuitesProvider.ResolveCipherParameterFactory(_cipherSuiteConfig.CipherSuite);
            
            var innerParameters = cipherParameterFactory.Create(end, direction);

            var nonceImplicit = GetImplicitNonce(direction);

            SecurityAssert.NotNull(nonceImplicit);
            SecurityAssert.Assert(nonceImplicit.Length > 0);
            
            var nonce = new byte[nonceImplicit.Length + nonceExplicit.Length];
            Array.Copy(nonceImplicit, 0, nonce, 0, nonceImplicit.Length);
            Array.Copy(nonceExplicit, 0, nonce, nonceImplicit.Length, nonceExplicit.Length);

            return new AADParameter(new IVParameter(innerParameters, nonce), aad);
        }

        private byte[] GetImplicitNonce(ConnectionDirection direction)
        {
            switch (_endConfig.End)
            {
                case ConnectionEnd.Client:
                    switch (direction)
                    {
                        case ConnectionDirection.Read:
                            return _aeadConfig.ServerIV ?? throw new InvalidOperationException("Server AEAD IV is not initialized");
                        case ConnectionDirection.Write:
                            return _aeadConfig.ClientIV ?? throw new InvalidOperationException("Client AEAD IV is not initialized");
                        default:
                            throw new ArgumentOutOfRangeException(nameof(direction), direction, null);
                    }
                case ConnectionEnd.Server:
                    switch (direction)
                    {
                        case ConnectionDirection.Read:
                            return _aeadConfig.ClientIV ?? throw new InvalidOperationException("Client AEAD IV is not initialized");
                        case ConnectionDirection.Write:
                            return _aeadConfig.ServerIV ?? throw new InvalidOperationException("Server AEAD IV is not initialized");
                        default:
                            throw new ArgumentOutOfRangeException(nameof(direction), direction, null);
                    }
                default:
                    throw new ArgumentOutOfRangeException(nameof(_endConfig.End), _endConfig.End, null);
            }
        }
    }
}
