using Moq;
using Xunit;

namespace Crypto.ASN1.Tests.Objects
{
    public class ASN1NullTests
    {
        [Fact]
        public void ByteLength_ShouldBeCorrect()
        {
            var b = new ASN1Null();

            Assert.Equal(0, b.ByteLength);
        }
        
        [Fact]
        public void Accept_ShouldCallWriterMethod()
        {
            var writerMock = new Mock<IASN1ObjectWriter>(MockBehavior.Strict);
            writerMock.Setup(x => x.Write(It.IsAny<ASN1Null>())).Verifiable();
            var sut = new ASN1Null();
            
            sut.Accept(writerMock.Object);
            
            writerMock.Verify(x => x.Write(sut), Times.Once);
        }
    }
}
