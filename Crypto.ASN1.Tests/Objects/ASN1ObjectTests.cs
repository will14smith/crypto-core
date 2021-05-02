using System.Collections.Generic;
using System.Numerics;
using Xunit;

namespace Crypto.ASN1.Tests.Objects
{
    public class ASN1ObjectTests
    {
        private class Test : ASN1Object
        {
            public Test(BigInteger byteLength) : base()
            {
                ByteLength = byteLength;
            }
            public Test(IEnumerable<ASN1Object> elements, BigInteger byteLength) : base(elements)
            {
                ByteLength = byteLength;
            }

            public override BigInteger ByteLength { get; }

            public override void Accept(IASN1ObjectWriter writer)
            {
                throw new System.NotSupportedException();
            }
        }

        [Fact]
        public void Elements_NoElements_ShouldHaveEmptyElements()
        {
            var o = new Test(0);

            Assert.Empty(o.Elements);
        }
        [Fact]
        public void Count_NoElements_ShouldBeZero()
        {
            var o = new Test(0);

            Assert.Equal(0, o.Count);
        }
        [Fact]
        public void Elements_SomeElements_ShouldHaveTheElements()
        {
            var o1 = new Test(0);
            var o2 = new Test(0);
            var o3 = new Test(0);
            var os = new[] { o1, o2, o3 };

            var o = new Test(os, 0);

            Assert.Equal(os, o.Elements);
        }
        [Fact]
        public void Count_SomeElements_ShouldNotBeZero()
        {
            var o1 = new Test(0);
            var o2 = new Test(0);
            var o3 = new Test(0);
            var os = new[] { o1, o2, o3 };

            var o = new Test(os, 0);

            Assert.Equal(os.Length, o.Count);
        }

        [Theory]
        [InlineData(0, 1)]
        [InlineData(0x7f, 1)]
        [InlineData(0x80, 2)]
        [InlineData(0xffff, 3)]
        public void LengthSize_ShouldBeCorrect(int byteLength, int expected)
        {
            var o = new Test(byteLength);

            Assert.Equal(expected, o.LengthSize);
        }
    }
}
