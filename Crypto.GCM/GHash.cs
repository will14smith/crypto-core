using System;
using Crypto.ASN1;
using Crypto.Core.Hashing;
using Crypto.Utils;

namespace Crypto.GCM
{
    public sealed class GHash : BlockDigest
    {
        private readonly ReadOnlyMemory<byte> _key;
        private readonly byte[] _y;

        public GHash(ReadOnlySpan<byte> key)
        {
            SecurityAssert.Assert(key.Length == 16);

            _key = key.Slice(0, 16).ToArray();

            _y = new byte[16];

            Reset();
        }

        private GHash(GHash clone) : base(clone)
        {
            _key = clone._key;

            _y = new byte[16];
            Array.Copy(clone._y, 0, _y, 0, 16);
        }

        public override ASN1ObjectIdentifier Id => null;

        public override int BlockSize => 128;
        public override int HashSize => 128;

        protected override void UpdateBlock(ReadOnlySpan<byte> buffer)
        {
            // y(i) = GM{128}(y(i-1) ^ buffer, key)
            for (var i = 0; i < 16; i++)
            {
                _y[i] ^= buffer[i];
            }

            var z = new byte[16];
            var v = _key.ToArray();

            for (var i = 0; i < 128; i++)
            {
                if ((_y[i / 8] & (1 << (7 - i % 8))) != 0)
                {
                    for (var j = 0; j < 16; j++)
                    {
                        z[j] ^= v[j];
                    }
                }

                var next = false;
                for (var j = 0; j < 16; j++)
                {
                    var t = (byte)(v[j] >> 1 | (next ? 0x80 : 0));
                    next = (v[j] & 0x1) != 0;

                    v[j] = t;
                }

                if (next)
                {
                    v[0] ^= 0xe1;
                }
            }

            Array.Copy(z, _y, 16);
        }

        public override ReadOnlySpan<byte> Digest()
        {
            SecurityAssert.Assert(WorkBufferEmpty);

            var digest = new byte[16];
            Array.Copy(_y, 0, digest, 0, 16);

            return digest;
        }

        public override void Reset()
        {
            base.Reset();

            Array.Clear(_y, 0, 16);
        }

        public override IDigest Clone()
        {
            return new GHash(this);
        }
    }
}
