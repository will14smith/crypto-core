using Xunit;

namespace Crypto.ASN1.Tests.Objects
{
    public class ASN1IntegerTests
    {
        public void ByteLength_ShouldBeCorrect()
        {
            Assert.Equal(1, new ASN1Integer(1).ByteLength);
            Assert.Equal(0xffff, new ASN1Integer(2).ByteLength);
            Assert.Equal(0xffffffff, new ASN1Integer(4).ByteLength);
        }
    }
}
