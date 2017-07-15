using System.Collections;
using Xunit;

namespace Crypto.ASN1.Tests.Objects
{
    public class ASN1BitStringTests
    {
        [Theory]
        [InlineData(7, 2)]
        [InlineData(8, 2)]
        [InlineData(9, 3)]
        [InlineData(128, 17)]
        public void ByteLength_ShouldBeCorrect(int length, int expected)
        {
            var b = new ASN1BitString(new BitArray(length));

            Assert.Equal(expected, b.ByteLength);
        }
    }
}
