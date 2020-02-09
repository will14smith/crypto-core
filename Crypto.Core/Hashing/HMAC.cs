using System;
using System.Collections.Generic;
using Crypto.ASN1;
using Crypto.Utils;

namespace Crypto.Core.Hashing
{
    public class HMAC : IDigest
    {
        private enum HMACState
        {
            Uninitialised = 0,
            ProcessedKey,
            InnerHashing,
            HashingDone
        }

        private readonly IDigest _digest;
        private readonly byte[] _key;

        private HMACState _state;

        public HMAC(IDigest digest, byte[] key)
        {
            SecurityAssert.NotNull(digest);
            SecurityAssert.NotNull(key);

            _digest = digest;
            _key = new byte[digest.BlockSize / 8];
            
            _state = HMACState.Uninitialised;
            ProcessInputKey(key);
            _state = HMACState.ProcessedKey;

            Reset();
        }

        public ASN1ObjectIdentifier Id => throw new NotImplementedException();
        public int BlockSize => _digest.BlockSize;
        public int HashSize => _digest.HashSize;

        public void Update(ReadOnlySpan<byte> input)
        {
            SecurityAssert.Assert(_state == HMACState.InnerHashing);

            _digest.Update(input);
        }

        public void Digest(Span<byte> output)
        {
            SecurityAssert.Assert(_state == HMACState.InnerHashing);

            _state = HMACState.HashingDone;

            var innerHash = _digest.DigestBuffer();

            var oPadKey = XorKey(_key, 0x5c);
            _digest.Reset();
            _digest.Update(oPadKey);
            _digest.Update(innerHash);

            _digest.Digest(output);
        }

        public void Reset()
        {
            SecurityAssert.Assert(_state != HMACState.Uninitialised);

            var iPadKey = XorKey(_key, 0x36);

            _digest.Reset();
            _digest.Update(iPadKey);

            _state = HMACState.InnerHashing;
        }

        public IDigest Clone()
        {
            throw new NotImplementedException();
        }

        private void ProcessInputKey(byte[] bytes)
        {
            var blockLength = _digest.BlockSize / 8;

            if (bytes.Length > blockLength)
            {
                _state = HMACState.Uninitialised;

                _digest.Reset();
                _digest.Update(bytes);
                _digest.Digest(_key.AsSpan());
            }
            else
            {
                Array.Copy(bytes, _key, bytes.Length);
            }

        }
        private static byte[] XorKey(IReadOnlyList<byte> bytes, byte param)
        {
            var result = new byte[bytes.Count];

            for (var i = 0; i < bytes.Count; i++)
            {
                result[i] = (byte)(bytes[i] ^ param);
            }

            return result;
        }

    }
}
