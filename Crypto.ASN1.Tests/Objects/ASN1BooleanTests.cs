using Xunit;

namespace Crypto.ASN1.Tests.Objects
{
    public class ASN1BooleanTests
    {
        [Fact]
        public void ByteLength_ShouldBeCorrect()
        {
            var b = new ASN1Boolean(true);

            Assert.Equal(1, b.ByteLength);
        }
    }
}
