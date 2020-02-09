using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Crypto.ASN1;
using Crypto.Core.Encryption.Parameters;
using Crypto.Core.Hashing;
using Crypto.Core.Randomness;
using Crypto.Core.Signing;
using Crypto.EC.Maths;
using Crypto.EC.Maths.Prime;
using Crypto.EC.Parameters;
using Crypto.Utils;

namespace Crypto.EC.Encryption
{
    public class ECDSA : ISignatureCipher
    {
        private int _ln;
        private PrimeField? _nField;

        private DomainParameters? _domain;
        private Point? _publicKey;
        private FieldValue? _privateKey;

        private readonly IRandom _random;

        public ECDSA(IRandom random)
        {
            _random = random;
        }

        public void Init(ICipherParameters parameters)
        {
            var ecParams = parameters as ECCipherParameters;
            if (ecParams == null)
            {
                throw new InvalidCastException("Expecting parameters of type ECCipherParameters");
            }

            _domain = ecParams.Domain;
            _publicKey = ecParams.PublicKey.Point;
            _privateKey = ecParams.PrivateKey?.D;

            _ln = _domain.Order.GetBitLength();
            _nField = new PrimeField(_domain.Order);
        }

        public byte[] Sign(byte[] input, IDigest hash)
        {
            if (_privateKey is null || _domain is null || _nField is null)
            {
                throw new InvalidOperationException("ECDSA not initialised");
            }

            // e = HASH(input)
            hash.Update(input);
            var e = hash.DigestBuffer();

            // z = the Ln leftmost bits of e, where Ln is the bit length of the group order n.
            var z = ToZ(e, _ln).Value;

            // k = rand(1, n-1) <-- step 3
            var k = _domain.Curve.Field.Value(_random.RandomBig(_domain.Order - 1));

            // (x1, y1) = k * G
            var c = Point.Multiply(_domain.Curve, k, _domain.Generator);

            // r = x1 % n
            var r = c.X.Value % _domain.Order;

            // if r == 0 go to step 3
            if (r == 0)
            {
                throw new NotImplementedException();
            }

            // s = (1/k)(z + rdA) mod n
            var kInv = _nField.Divide(_nField.Value(1), k);
            var s = _nField.Multiply(kInv, _nField.Value(z + r * _privateKey.Value)).Value;

            // if s == 0 go to step 3
            if (s == 0)
            {
                throw new NotImplementedException();
            }

            // return ASN1 SEQUENCE [r INTEGER, s INTEGER]
            using (var buffer = new MemoryStream())
            {
                var derWriter = new DERWriter(buffer);

                derWriter.Write(new ASN1Sequence(new[]
                {
                    new ASN1Integer(r),
                    new ASN1Integer(s),
                }));

                return buffer.ToArray();
            }
        }

        private FieldValue ToZ(IEnumerable<byte> e, int ln)
        {
            if (_domain is null) { throw new InvalidOperationException("ECDSA not initialised"); }            
            
            // TODO handle sub byte lengths

            if (ln % 8 != 0)
            {
                throw new NotImplementedException();
            }

            return _domain.Field.Value(e.Take(ln / 8).ToBigInteger());
        }

        public bool Verify(byte[] input, byte[] signature, IDigest hash)
        {
            if (_publicKey is null || _domain is null || _nField is null) { throw new InvalidOperationException("ECDSA not initialised"); }            

            FieldValue r, s;

            using (var buffer = new MemoryStream(signature))
            {
                var reader = new DERReader(buffer);

                var seq = reader.Read() as ASN1Sequence;
                SecurityAssert.NotNull(seq);
                SecurityAssert.Assert(seq!.Count == 2);

                var ri = seq.Elements[0] as ASN1Integer;
                SecurityAssert.NotNull(ri);
                r = _nField.Value(ri!.Value);
                SecurityAssert.Assert(r.Value == ri!.Value);

                var si = seq.Elements[1] as ASN1Integer;
                SecurityAssert.NotNull(si);
                s = _nField.Value(si!.Value);
                SecurityAssert.Assert(s.Value == si!.Value);
            }

            // check QA != O
            // check QA is on curve
            SecurityAssert.Assert(_domain.Curve.IsPointOnCurve(_publicKey));
            // check n*QA = O
            // check r and s are in [1, n-1]

            // e = HASH(input)
            hash.Update(input);
            var e = hash.DigestBuffer();

            // z = the Ln leftmost bits of e, where Ln is the bit length of the group order n.
            var z = ToZ(e, _ln);

            // w = 1/s (mod n)
            var w = _nField.Divide(_nField.Value(1), s);

            // u1 = zw (mod n)
            var u1 = _nField.Multiply(w, z);

            // u2 = rw (mod n)
            var u2 = _nField.Multiply(w, r);

            // (x1, y2) = u1 * G + u2 * QA
            var point = Point.Add(_domain.Curve,
                    a: Point.Multiply(_domain.Curve, u1, _domain.Generator),
                    b: Point.Multiply(_domain.Curve, u2, _publicKey))!;

            // return r == x1 (mod n)
            return r == point.X;
        }
    }
}
