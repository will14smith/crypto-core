using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Text;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.ASN1
{
    public class DERWriter : IASN1ObjectWriter
    {
        private readonly EndianBinaryWriter _writer;

        public DERWriter(Stream stream)
        {
            _writer = new EndianBinaryWriter(EndianBitConverter.Big, stream);
        }

        public void Write(ASN1Object obj)
        {
            obj.Accept(this);
        }

        public void Write(ASN1BitString value)
        {
            WriteIdentifier(ASN1Class.Universal, false, ASN1UniversalTag.BitString);
            WriteLength(value.ByteLength);

            var array = value.Value;

            _writer.Write((byte)(array.Length % 8));
            for (var i = 0; i < array.Length; i += 8)
            {
                if (i + 8 >= array.Length)
                {
                    _writer.Write((byte)(array.GetByte(i) << (8 - (array.Length - i))));
                }
                else
                {
                    _writer.Write(array.GetByte(i));
                }
            }
        }

        public void Write(ASN1Boolean value)
        {
            WriteIdentifier(ASN1Class.Universal, false, ASN1UniversalTag.Boolean);
            WriteLength(value.ByteLength);
            _writer.Write((byte)(value.Value ? 255 : 0));
        }

        public void Write(ASN1Integer value)
        {
            WriteIdentifier(ASN1Class.Universal, false, ASN1UniversalTag.Integer);
            WriteLength(value.ByteLength);

            var buffer = value.Value.ToByteArray();
            // convert to big endian
            Array.Reverse(buffer);

            _writer.Write(buffer);
        }

        public void Write(ASN1Null value)
        {
            WriteIdentifier(ASN1Class.Universal, false, ASN1UniversalTag.Null);
            WriteLength(value.ByteLength);
        }

        public void Write(ASN1ObjectIdentifier value)
        {
            WriteIdentifier(ASN1Class.Universal, false, ASN1UniversalTag.ObjectIdentifier);
            WriteLength(value.ByteLength);
            _writer.Write(ASN1ObjectIdentifier.GetBytes(value.Identifier));
        }

        public void Write(ASN1OctetString value)
        {
            WriteIdentifier(ASN1Class.Universal, false, ASN1UniversalTag.OctetString);
            WriteLength(value.ByteLength);
            _writer.Write(value.Value);
        }

        public void Write(ASN1Sequence value)
        {
            WriteIdentifier(ASN1Class.Universal, true, ASN1UniversalTag.Sequence);
            WriteLength(value.ByteLength);
            WriteChildren(value);
        }

        public void Write(ASN1Set value)
        {
            WriteIdentifier(ASN1Class.Universal, true, ASN1UniversalTag.Set);
            WriteLength(value.ByteLength);

            var children = new Dictionary<BigInteger, byte[]>();
            foreach (var child in value.Elements)
            {
                byte[] buffer;
                using (var ms = new MemoryStream())
                {
                    new DERWriter(ms).Write(child);

                    buffer = ms.ToArray();
                }

                var tag = ReadTag(buffer);

                children.Add(tag, buffer);
            }

            foreach (var child in children.OrderBy(x => x.Key))
            {
                _writer.Write(child.Value);
            }
        }

        public void Write(ASN1Tagged value)
        {
            WriteIdentifier(ASN1Class.Context, true, value.Tag);
            WriteLength(value.ByteLength);
            WriteChildren(value);
        }

        public void Write(ASN1TaggedPrimitive value)
        {
            WriteIdentifier(ASN1Class.Context, false, value.Tag);
            WriteLength(value.ByteLength);
            _writer.Write(value.Value);
        }

        public void Write(ASN1UTCTime value)
        {
            WriteIdentifier(ASN1Class.Universal, false, ASN1UniversalTag.UTCTime);
            WriteLength(value.ByteLength);
            _writer.Write(Encoding.UTF8.GetBytes(value.Value.ToString("yyMMddHHmmssZ")));
        }

        public void Write(ASN1PrintableString value)
        {
            WriteIdentifier(ASN1Class.Universal, false, ASN1UniversalTag.PrintableString);
            WriteLength(value.ByteLength);
            _writer.Write(Encoding.ASCII.GetBytes(value.Value));
        }

        public void Write(ASN1UTF8String value)
        {
            WriteIdentifier(ASN1Class.Universal, false, ASN1UniversalTag.UTF8String);
            WriteLength(value.ByteLength);
            _writer.Write(Encoding.UTF8.GetBytes(value.Value));
        }

        // helpers
        private void WriteIdentifier(ASN1Class asn1Class, bool constructed, ASN1UniversalTag tag)
        {
            WriteIdentifier(asn1Class, constructed, (byte)tag);
        }
        private void WriteIdentifier(ASN1Class asn1Class, bool constructed, BigInteger tag)
        {
            SecurityAssert.Assert(tag >= 0);

            if (tag > 31)
            {
                throw new NotImplementedException();
            }

            var id = (byte)(((byte)asn1Class << 6) | (constructed ? 0x20 : 0) | ((byte)tag));
            _writer.Write(id);
        }

        private void WriteLength(BigInteger length)
        {
            SecurityAssert.Assert(length >= 0);

            if (length >= 0x80)
            {
                var lengthBuffer = length.ToByteArray().Reverse().ToArray();
                var lengthSize = (byte)((lengthBuffer.Length & 0x7f) | 0x80);

                _writer.Write(lengthSize);
                _writer.Write(lengthBuffer);
            }
            else
            {
                _writer.Write((byte)length);
            }
        }

        private void WriteChildren(ASN1Object value)
        {
            foreach (var elem in value.Elements)
            {
                Write(elem);
            }
        }

        private BigInteger ReadTag(IReadOnlyList<byte> buffer)
        {
            SecurityAssert.Assert(buffer.Count > 0);

            if ((buffer[0] & 0x1f) == 0x1f)
            {
                throw new NotImplementedException();
            }

            return buffer[0] & 0x1f;
        }
    }
}
