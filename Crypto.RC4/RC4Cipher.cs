using System;
using System.Collections.Generic;
using Crypto.Core.Encryption;
using Crypto.Core.Encryption.Parameters;
using Crypto.Utils;

namespace Crypto.RC4
{
    public class RC4Cipher : ICipher
    {
        private bool _keyInitialised;
        private readonly byte[] _key;
        private readonly byte[] _s;

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
            Array.Copy(keyParam, _key, KeySize);

            var tmp = BuildSchedule(_key);
            Array.Copy(tmp, _s, _s.Length);

            _i = 0;
            _j = 0;
            
            _keyInitialised = true;
        }

        public void Encrypt(byte[] input, int inputOffset, byte[] output, int outputOffset, int length)
        {
            SecurityAssert.Assert(_keyInitialised);
            SecurityAssert.AssertBuffer(input, inputOffset, length);
            SecurityAssert.AssertBuffer(output, outputOffset, length);

            for (var offset = 0; offset < length; offset++)
            {
                output[outputOffset + offset] = (byte)(input[inputOffset + offset] ^ NextPGRA());
            }
        }

        public void Decrypt(byte[] input, int inputOffset, byte[] output, int outputOffset, int length)
        {
            Encrypt(input, inputOffset, output, outputOffset, length);
        }

        private static byte[] BuildSchedule(IReadOnlyList<byte> key)
        {
            var s = new byte[256];

            for (var i = 0; i < s.Length; i++)
            {
                s[i] = (byte)i;
            }

            var j = 0;

            for (var i = 0; i < s.Length; i++)
            {
                j = (j + s[i] + key[i % key.Count]) % 256;

                (s[i], s[j]) = (s[j], s[i]);
            }

            return s;
        }

        private byte NextPGRA()
        {
            _i = (_i + 1) % 256;
            _j = (_j + _s[_i]) % 256;
            (_s[_i], _s[_j]) = (_s[_j], _s[_i]);
            return _s[(_s[_i] + _s[_j]) % 256];
        }
    }
}
