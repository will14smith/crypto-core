using System;
using System.Collections.Generic;
using System.Numerics;
using System.Security;
using System.Text;
using Moq;
using Xunit;
using Crypto.Core.Randomness;

namespace Crypto.Core.Tests.Randomness
{
    public class RandomExtensionsTests
    {
        [Theory]
        [InlineData(-1)]
        public void RandomNonZeroBytes_InvalidCases(int n)
        {
            Assert.Throws<SecurityException>(() => Mock.Of<IRandom>().RandomNonZeroBytes(n));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(3)]
        [InlineData(200)]
        public void RandomNonZeroBytes_ShouldCallRandomIntNTimes(int n)
        {
            var randomMock = new Mock<IRandom>(MockBehavior.Strict);
            randomMock.Setup(x => x.RandomInt(1, 255)).Returns(4).Verifiable();

            var result = randomMock.Object.RandomNonZeroBytes(n);

            Assert.Equal(n, result.Length);
            randomMock.Verify(x => x.RandomInt(1, 255), Times.Exactly(n));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(7)]
        public void RandomBig_InvalidCases(int bits)
        {
            Assert.Throws<SecurityException>(() => Mock.Of<IRandom>().RandomBig(bits));
        }

        [Theory]
        [InlineData(8)]
        [InlineData(256)]
        public void RandomBig_ShouldGetNRandomBytes(int bits)
        {
            var n = bits / 8;

            var randomMock = new Mock<IRandom>(MockBehavior.Strict);
            randomMock.Setup(x => x.RandomBytes(n)).Returns(new byte[n]).Verifiable();

            randomMock.Object.RandomBig(bits);

            randomMock.Verify(x => x.RandomBytes(n), Times.Once);
        }

        [Fact]
        public void RandomBig_ShouldReturnPositiveNumber()
        {
            var random = Mock.Of<IRandom>(x => x.RandomBytes(1) == new byte[] { 0x80 });

            var result = random.RandomBig(8);

            Assert.Equal(0x80, result);
        }

        [Fact]
        public void RandomBig_WithMax_ShouldRetryUntilUnderMax()
        {
            var randomMock = new Mock<IRandom>(MockBehavior.Strict);

            var attempt = 0;
            randomMock.Setup(x => x.RandomBytes(1)).Returns(() =>
            {
                if (attempt++ == 0)
                {
                    return new byte[] { 0x11 };
                }

                return new byte[] { 0x10 };
            }).Verifiable();

            var result = randomMock.Object.RandomBig(new BigInteger(0x10));

            Assert.Equal(0x10, result);
            randomMock.Verify(x => x.RandomBytes(1), Times.Exactly(2));
        }
    }
}
