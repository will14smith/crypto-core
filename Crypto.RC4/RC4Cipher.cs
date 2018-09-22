using System;
using Crypto.Core.Encryption;
using Crypto.Core.Encryption.Parameters;
using Crypto.Utils;

namespace Crypto.RC4
{
    public class RC4Cipher : ICipher
    {
        private bool _keyInitialised;
        private readonly Memory<byte> _key;
        private readonly Memory<byte> _s;

        private int _i;
        private int _j;

        public int KeySize { get; }

        public RC4Cipher(int keySize)
        {
            SecurityAssert.Assert(keySize % 8 == 0);

            KeySize = keySize / 8;

            _key = new byte[KeySize];
            _s = new byte[256];
        }

        public void Init(ICipherParameters parameters)
        {
            var keyParams = parameters as RC4KeyParameter;

            if (keyParams == null)
            {
                throw new InvalidCastException();
            }

            var keyParam = keyParams.Key;

            SecurityAssert.NotNull(keyParam);
            SecurityAssert.Assert(keyParam.Length == KeySize);
            keyParam.CopyTo(_key);

            BuildSchedule(_key.Span, _s.Span);

            _i = 0;
            _j = 0;
            
            _keyInitialised = true;
        }

        public void Encrypt(ReadOnlySpan<byte> input, Span<byte> output)
        {
            SecurityAssert.Assert(_keyInitialised);
            SecurityAssert.AssertInputOutputBuffers(input, output);

            for (var offset = 0; offset < output.Length; offset++)
            {
                output[offset] = (byte)(input[ offset] ^ NextPGRA(_s.Span));
            }
        }

        public void Decrypt(ReadOnlySpan<byte> input, Span<byte> output)
        {
            Encrypt(input, output);
        }

        private static void BuildSchedule(ReadOnlySpan<byte> key, Span<byte> schedule)
        {
            for (var i = 0; i < schedule.Length; i++)
            {
                schedule[i] = (byte)i;
            }

            var j = 0;

            for (var i = 0; i < schedule.Length; i++)
            {
                j = (j + schedule[i] + key[i % key.Length]) % 256;

                (schedule[i], schedule[j]) = (schedule[j], schedule[i]);
            }
        }

        private byte NextPGRA(Span<byte> schedule)
        {
            _i = (_i + 1) % 256;
            _j = (_j + schedule[_i]) % 256;
            (schedule[_i], schedule[_j]) = (schedule[_j], schedule[_i]);
            return schedule[(schedule[_i] + schedule[_j]) % 256];
        }
    }
}
