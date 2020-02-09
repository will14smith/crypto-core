using System;
using Crypto.ASN1;
using Crypto.Core.Hashing;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.SHA
{
    public sealed class SHA1Digest : BlockDigest
    {
        public override ASN1ObjectIdentifier Id => new ASN1ObjectIdentifier("1.3.14.3.2.26");
        public override int BlockSize => 512;
        public override int HashSize => 160;

        private uint _h0;
        private uint _h1;
        private uint _h2;
        private uint _h3;
        private uint _h4;

        private bool _complete;

        public SHA1Digest()
        {
            Reset();
        }

        private SHA1Digest(SHA1Digest source)
            : base(source)
        {
            _h0 = source._h0;
            _h1 = source._h1;
            _h2 = source._h2;
            _h3 = source._h3;
            _h4 = source._h4;

            _complete = source._complete;
        }

        public override void Reset()
        {
            base.Reset();

            _h0 = 0x67452301;
            _h1 = 0xEFCDAB89;
            _h2 = 0x98BADCFE;
            _h3 = 0x10325476;
            _h4 = 0xC3D2E1F0;

            _complete = false;
        }

        public override IDigest Clone()
        {
            return new SHA1Digest(this);
        }

        public override void Update(ReadOnlySpan<byte> input)
        {
            SecurityAssert.Assert(!_complete);

            base.Update(input);
        }

        protected override void UpdateBlock(byte[] buffer)
        {
            SecurityAssert.Assert(!_complete);

            var w = new uint[80];
            for (var i = 0; i < 16; i++)
            {
                w[i] = EndianBitConverter.Big.ToUInt32(buffer, i << 2);
            }
            for (var i = 16; i < 80; i++) { w[i] = LeftRotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1); }

            var a = _h0;
            var b = _h1;
            var c = _h2;
            var d = _h3;
            var e = _h4;

            for (var i = 0; i < 80; i++)
            {
                uint f, k;
                if (i < 20)
                {
                    f = (b & c) | (~b & d);
                    k = 0x5A827999;
                }
                else if (i < 40)
                {
                    f = b ^ c ^ d;
                    k = 0x6ED9EBA1;
                }
                else if (i < 60)
                {
                    f = (b & c) | (b & d) | (c & d);
                    k = 0x8F1BBCDC;
                }
                else
                {
                    f = b ^ c ^ d;
                    k = 0xCA62C1D6;
                }

                var temp = LeftRotate(a, 5) + f + e + k + w[i];
                e = d;
                d = c;
                c = LeftRotate(b, 30);
                b = a;
                a = temp;
            }

            _h0 += a;
            _h1 += b;
            _h2 += c;
            _h3 += d;
            _h4 += e;
        }

        private static uint LeftRotate(uint value, int amount)
        {
            SecurityAssert.Assert(0 <= amount && amount < 32);

            var a = value << amount;
            var b = value >> (32 - amount);

            return a | b;
        }

        public override void Digest(Span<byte> output)
        {
            SecurityAssert.AssertBuffer(output, HashSize / 8);
            
            var paddingLength = 64 - MessageSize % BlockSize / 8;
            if (paddingLength <= 8) paddingLength += 64;

            var padding = new byte[paddingLength];
            // first bit is 1
            padding[0] = 0x80;

            Array.Copy(EndianBitConverter.Big.GetBytes(MessageSize), 0, padding, paddingLength - 8, 8);

            Update(padding);
            SecurityAssert.Assert(WorkBufferEmpty);

            _complete = true;
            
            EndianBitConverter.Big.GetBytes(_h0).CopyTo(output);
            EndianBitConverter.Big.GetBytes(_h1).CopyTo(output.Slice(4));
            EndianBitConverter.Big.GetBytes(_h2).CopyTo(output.Slice(8));
            EndianBitConverter.Big.GetBytes(_h3).CopyTo(output.Slice(12));
            EndianBitConverter.Big.GetBytes(_h4).CopyTo(output.Slice(16));
        }
    }
}
