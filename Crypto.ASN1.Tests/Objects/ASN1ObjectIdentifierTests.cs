using System.Security;
using Xunit;

namespace Crypto.ASN1.Tests.Objects
{
    public class ASN1ObjectIdentifierTests
    {
        [Fact]
        public void Equals_WhenEqual_ShouldBeTrue()
        {
            var a = new ASN1ObjectIdentifier("1.3.6");
            var b = new ASN1ObjectIdentifier("1.3.6");

            Assert.True(a.Equals(a));
            Assert.True(a.Equals(b));
        }
        [Fact]
        public void Equals_WhenDifferent_ShouldBeFalse()
        {
            var a = new ASN1ObjectIdentifier("1.3.6");
            var b = new ASN1ObjectIdentifier("1.3.7");

            Assert.False(a.Equals(null));
            Assert.False(a.Equals(b));
        }

        [Fact]
        public void Format_Null_FailsAssertion()
        {
            Assert.Throws<SecurityException>(() => ASN1ObjectIdentifier.Format(null));
        }
        [Fact]
        public void Format_Empty_FailsAssertion()
        {
            Assert.Throws<SecurityException>(() => ASN1ObjectIdentifier.Format(new byte[0]));
        }

        [Fact]
        public void Format_InvalidBase128_FailsAssertion()
        {
            Assert.Throws<SecurityException>(() => ASN1ObjectIdentifier.Format(new byte[] { 1, 129 }));
        }

        [Fact]
        public void Format_FirstByte_Has2CorrectElements()
        {
            var input = new byte[] { 43 };

            var result = ASN1ObjectIdentifier.Format(input);

            Assert.Equal("1.3", result);
        }

        [Fact]
        public void Format_Base128Single_HasCorrectElements()
        {
            var input = new byte[] { 43, 4 };

            var result = ASN1ObjectIdentifier.Format(input);

            Assert.Equal("1.3.4", result);

        }

        [Fact]
        public void Format_Base128Multiple_HasCorrectElements()
        {
            var input = new byte[] { 43, 129, 4, 1 };

            var result = ASN1ObjectIdentifier.Format(input);

            Assert.Equal("1.3.132.1", result);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("1")]
        [InlineData("-1.1")]
        [InlineData("7.1")]
        [InlineData("1.-1")]
        [InlineData("1.41")]
        [InlineData("1.3.-1")]
        public void GetBytes_FailsAssertion(string input)
        {
            Assert.Throws<SecurityException>(() => ASN1ObjectIdentifier.GetBytes(input));
        }

        [Theory]
        [InlineData("1.3", new byte[] { 43 })]
        [InlineData("1.3.4", new byte[] { 43, 4 })]
        [InlineData("1.3.4", new byte[] { 43, 4 })]
        [InlineData("1.3.132.1", new byte[] { 43, 129, 4, 1 })]
        public void GetBytes_WorksCorrectly(string input, byte[] expected)
        {
            Assert.Equal(expected, ASN1ObjectIdentifier.GetBytes(input));
        }
    }
}
