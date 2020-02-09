using System;
using Crypto.ASN1;
using Crypto.Core.Hashing;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.SHA
{
    public sealed class SHA256Digest : BlockDigest
    {
        public enum Mode
        {
            SHA256,
            SHA224
        }

        public override ASN1ObjectIdentifier Id =>
            _mode == Mode.SHA224
                ? throw new NotImplementedException()
                : new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1");

        public override int BlockSize => 512;
        public override int HashSize => _mode == Mode.SHA224 ? 224 : 256;

        private uint _h0;
        private uint _h1;
        private uint _h2;
        private uint _h3;
        private uint _h4;
        private uint _h5;
        private uint _h6;
        private uint _h7;

        private static readonly uint[] K = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        private readonly Mode _mode;
        private bool _complete;

        public SHA256Digest(Mode mode)
        {
            _mode = mode;

            Reset();
        }

        private SHA256Digest(SHA256Digest source)
            : base(source)
        {
            _h0 = source._h0;
            _h1 = source._h1;
            _h2 = source._h2;
            _h3 = source._h3;
            _h4 = source._h4;
            _h5 = source._h5;
            _h6 = source._h6;
            _h7 = source._h7;

            _mode = source._mode;
            _complete = source._complete;
        }

        public override void Update(byte[] buffer, int offset, int length)
        {
            SecurityAssert.Assert(!_complete);

            base.Update(buffer, offset, length);
        }

        public override IDigest Clone()
        {
            return new SHA256Digest(this);
        }

        protected override void UpdateBlock(byte[] buffer)
        {
            SecurityAssert.Assert(!_complete);

            var w = new uint[64];
            for (var i = 0; i < 16; i++)
            {
                w[i] = EndianBitConverter.Big.ToUInt32(buffer, i << 2);
            }
            for (var i = 16; i < 64; i++)
            {
                var s0 = RightRotate(w[i - 15], 7) ^ RightRotate(w[i - 15], 18) ^ (w[i - 15] >> 3);
                var s1 = RightRotate(w[i - 2], 17) ^ RightRotate(w[i - 2], 19) ^ (w[i - 2] >> 10);

                w[i] = w[i - 16] + s0 + w[i - 7] + s1;
            }

            var a = _h0;
            var b = _h1;
            var c = _h2;
            var d = _h3;
            var e = _h4;
            var f = _h5;
            var g = _h6;
            var h = _h7;

            for (var i = 0; i < 64; i++)
            {
                var s1 = RightRotate(e, 6) ^ RightRotate(e, 11) ^ RightRotate(e, 25);
                var ch = (e & f) ^ (~e & g);
                var temp1 = h + s1 + ch + K[i] + w[i];
                var s0 = RightRotate(a, 2) ^ RightRotate(a, 13) ^ RightRotate(a, 22);
                var maj = (a & b) ^ (a & c) ^ (b & c);
                var temp2 = s0 + maj;

                h = g;
                g = f;
                f = e;
                e = d + temp1;
                d = c;
                c = b;
                b = a;
                a = temp1 + temp2;
            }

            _h0 += a;
            _h1 += b;
            _h2 += c;
            _h3 += d;
            _h4 += e;
            _h5 += f;
            _h6 += g;
            _h7 += h;
        }

        private uint RightRotate(uint value, int amount)
        {
            SecurityAssert.Assert(0 <= amount && amount < 32);

            var a = value >> amount;
            var b = value << (32 - amount);

            return a | b;
        }

        public override byte[] Digest()
        {
            // TODO same as SHA1...

            var paddingLength = 64 - (MessageSize % BlockSize) / 8;
            if (paddingLength <= 8) paddingLength += 64;

            var padding = new byte[paddingLength];
            // first bit is 1
            padding[0] = 0x80;

            Array.Copy(EndianBitConverter.Big.GetBytes(MessageSize), 0, padding, paddingLength - 8, 8);

            this.Update(padding);
            SecurityAssert.Assert(WorkBufferEmpty);

            _complete = true;

            var digest = _mode == Mode.SHA224 ? new byte[28] : new byte[32];

            Array.Copy(EndianBitConverter.Big.GetBytes(_h0), 0, digest, 0, 4);
            Array.Copy(EndianBitConverter.Big.GetBytes(_h1), 0, digest, 4, 4);
            Array.Copy(EndianBitConverter.Big.GetBytes(_h2), 0, digest, 8, 4);
            Array.Copy(EndianBitConverter.Big.GetBytes(_h3), 0, digest, 12, 4);
            Array.Copy(EndianBitConverter.Big.GetBytes(_h4), 0, digest, 16, 4);
            Array.Copy(EndianBitConverter.Big.GetBytes(_h5), 0, digest, 20, 4);
            Array.Copy(EndianBitConverter.Big.GetBytes(_h6), 0, digest, 24, 4);
            if (_mode == Mode.SHA256)
                Array.Copy(EndianBitConverter.Big.GetBytes(_h7), 0, digest, 28, 4);

            return digest;
        }

        public override void Reset()
        {
            base.Reset();

            _complete = false;

            if (_mode == Mode.SHA224)
            {
                _h0 = 0xc1059ed8;
                _h1 = 0x367cd507;
                _h2 = 0x3070dd17;
                _h3 = 0xf70e5939;
                _h4 = 0xffc00b31;
                _h5 = 0x68581511;
                _h6 = 0x64f98fa7;
                _h7 = 0xbefa4fa4;
            }
            else
            {
                _h0 = 0x6a09e667;
                _h1 = 0xbb67ae85;
                _h2 = 0x3c6ef372;
                _h3 = 0xa54ff53a;
                _h4 = 0x510e527f;
                _h5 = 0x9b05688c;
                _h6 = 0x1f83d9ab;
                _h7 = 0x5be0cd19;
            }
        }
    }
}
