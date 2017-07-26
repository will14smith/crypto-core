using System;
using Crypto.ASN1;
using Crypto.Core.Hashing;
using Crypto.Utils;

namespace Crypto.SHA
{
    public sealed class SHA512Digest : BlockDigest
    {
        public enum Mode
        {
            SHA384,
            SHA512
        }

        public override ASN1ObjectIdentifier Id => new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.3");

        public override int BlockSize => 1024;
        public override int HashSize => _mode == Mode.SHA384 ? 384 : 512;

        private ulong _h0;
        private ulong _h1;
        private ulong _h2;
        private ulong _h3;
        private ulong _h4;
        private ulong _h5;
        private ulong _h6;
        private ulong _h7;

        private static readonly ulong[] K = {
            0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
            0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
            0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
            0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
            0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
            0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
            0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
            0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
            0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
            0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
            0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
            0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
            0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
            0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
            0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
        };

        private readonly Mode _mode;
        private bool _complete;

        public SHA512Digest(Mode mode)
        {
            _mode = mode;
            Reset();
        }

        private SHA512Digest(SHA512Digest source)
            : base(source)
        {
            _mode = source._mode;

            _h0 = source._h0;
            _h1 = source._h1;
            _h2 = source._h2;
            _h3 = source._h3;
            _h4 = source._h4;
            _h5 = source._h5;
            _h6 = source._h6;
            _h7 = source._h7;

            _complete = source._complete;
        }

        public override void Update(byte[] buffer, int offset, int length)
        {
            SecurityAssert.Assert(!_complete);

            base.Update(buffer, offset, length);
        }

        public override IDigest Clone()
        {
            return new SHA512Digest(this);
        }

        protected override void UpdateBlock(byte[] buffer)
        {
            SecurityAssert.Assert(!_complete);

            var w = new ulong[80];
            for (var i = 0; i < 16; i++)
            {
                w[i] = EndianBitConverter.Big.ToUInt64(buffer, i << 3);
            }
            for (var i = 16; i < 80; i++)
            {
                var s0 = RightRotate(w[i - 15], 1) ^ RightRotate(w[i - 15], 8) ^ (w[i - 15] >> 7);
                var s1 = RightRotate(w[i - 2], 19) ^ RightRotate(w[i - 2], 61) ^ (w[i - 2] >> 6);

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

            for (var i = 0; i < 80; i++)
            {
                var s1 = RightRotate(e, 14) ^ RightRotate(e, 18) ^ RightRotate(e, 41);
                var ch = (e & f) ^ (~e & g);
                var temp1 = h + s1 + ch + K[i] + w[i];
                var s0 = RightRotate(a, 28) ^ RightRotate(a, 34) ^ RightRotate(a, 39);
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

        private ulong RightRotate(ulong value, int amount)
        {
            SecurityAssert.Assert(0 <= amount && amount < 64);

            var a = value >> amount;
            var b = value << (64 - amount);

            return a | b;
        }

        public override byte[] Digest()
        {
            // TODO same as SHA1...

            var paddingLength = 128 - (MessageSize % BlockSize) / 8;
            if (paddingLength <= 16) paddingLength += 128;

            var padding = new byte[paddingLength];
            // first bit is 1
            padding[0] = 0x80;

            // TODO messagesize should be 128-bits, this only 64 bits and the upper 64 are implicity zeroed in the padding
            Array.Copy(EndianBitConverter.Big.GetBytes(MessageSize), 0, padding, paddingLength - 8, 8);

            Update(padding, 0, padding.Length);
            SecurityAssert.Assert(WorkBufferEmpty);

            _complete = true;

            var digest = _mode == Mode.SHA384 ? new byte[48] : new byte[64];

            Array.Copy(EndianBitConverter.Big.GetBytes(_h0), 0, digest, 0, 8);
            Array.Copy(EndianBitConverter.Big.GetBytes(_h1), 0, digest, 8, 8);
            Array.Copy(EndianBitConverter.Big.GetBytes(_h2), 0, digest, 16, 8);
            Array.Copy(EndianBitConverter.Big.GetBytes(_h3), 0, digest, 24, 8);
            Array.Copy(EndianBitConverter.Big.GetBytes(_h4), 0, digest, 32, 8);
            Array.Copy(EndianBitConverter.Big.GetBytes(_h5), 0, digest, 40, 8);
            if (_mode == Mode.SHA512)
            {
                Array.Copy(EndianBitConverter.Big.GetBytes(_h6), 0, digest, 48, 8);
                Array.Copy(EndianBitConverter.Big.GetBytes(_h7), 0, digest, 56, 8);
            }

            return digest;
        }

        public override void Reset()
        {
            base.Reset();

            _complete = false;

            if (_mode == Mode.SHA384)
            {
                _h0 = 0xcbbb9d5dc1059ed8;
                _h1 = 0x629a292a367cd507;
                _h2 = 0x9159015a3070dd17;
                _h3 = 0x152fecd8f70e5939;
                _h4 = 0x67332667ffc00b31;
                _h5 = 0x8eb44a8768581511;
                _h6 = 0xdb0c2e0d64f98fa7;
                _h7 = 0x47b5481dbefa4fa4;
            }
            else
            {
                _h0 = 0x6a09e667f3bcc908;
                _h1 = 0xbb67ae8584caa73b;
                _h2 = 0x3c6ef372fe94f82b;
                _h3 = 0xa54ff53a5f1d36f1;
                _h4 = 0x510e527fade682d1;
                _h5 = 0x9b05688c2b3e6c1f;
                _h6 = 0x1f83d9abfb41bd6b;
                _h7 = 0x5be0cd19137e2179;
            }
        }
    }
}
