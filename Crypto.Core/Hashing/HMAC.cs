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
        private readonly ReadOnlyMemory<byte> _key;

        private HMACState _state;

        public HMAC(IDigest digest, ReadOnlySpan<byte> inputKey)
        {
            SecurityAssert.NotNull(digest);

            _digest = digest;
           
            _state = HMACState.Uninitialised;

            var key = new byte[digest.BlockSize / 8];
            ProcessInputKey(inputKey, key);
            _key = key;

            _state = HMACState.ProcessedKey;

            Reset();
        }

        public ASN1ObjectIdentifier Id => null;
        public int BlockSize => _digest.BlockSize;
        public int HashSize => _digest.HashSize;

        public void Update(ReadOnlySpan<byte> buffer)
        {
            SecurityAssert.Assert(_state == HMACState.InnerHashing);

            _digest.Update(buffer);
        }

        public ReadOnlySpan<byte> Digest()
        {
            SecurityAssert.Assert(_state == HMACState.InnerHashing);

            _state = HMACState.HashingDone;

            var innerHash = _digest.Digest();

            var oPadKey = XorKey(_key.Span, 0x5c);
            _digest.Reset();
            _digest.Update(oPadKey);
            _digest.Update(innerHash);

            return _digest.Digest();
        }

        public void Reset()
        {
            SecurityAssert.Assert(_state != HMACState.Uninitialised);

            var iPadKey = XorKey(_key.Span, 0x36);

            _digest.Reset();
            _digest.Update(iPadKey);

            _state = HMACState.InnerHashing;
        }

        public IDigest Clone()
        {
            throw new NotImplementedException();
        }

        private void ProcessInputKey(ReadOnlySpan<byte> input, Span<byte> output)
        {
            var blockLength = _digest.BlockSize / 8;

            if (input.Length > blockLength)
            {
                _digest.Reset();
                _digest.Update(input);
                _digest.Digest().CopyTo(output);
            }
            else
            {
                input.CopyTo(output);
            }

        }
        private static ReadOnlySpan<byte> XorKey(ReadOnlySpan<byte> bytes, byte param)
        {
            var result = new byte[bytes.Length];

            for (var i = 0; i < bytes.Length; i++)
            {
                result[i] = (byte)(bytes[i] ^ param);
            }

            return result;
        }

    }
}
