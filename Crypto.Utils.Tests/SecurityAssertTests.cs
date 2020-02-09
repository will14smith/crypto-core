using System.Security;
using System.Threading;
using Xunit;

namespace Crypto.Utils.Tests
{
    public class SecurityAssertTests
    {
        [Fact]
        public void NotNull_WhenNotNull_ShouldDoNothing()
        {
            var a = Thread.CurrentThread;

            SecurityAssert.NotNull(a);
        }

        [Fact]
        public void NotNull_WhenNull_ShouldThrowSecurityException()
        {
            Thread? a = null;

            Assert.Throws<SecurityException>(() => SecurityAssert.NotNull(a));
        }

        [Fact]
        public void SAssert_WhenTrue_ShouldDoNothing()
        {
            SecurityAssert.Assert(true);
        }

        [Fact]
        public void SAssert_WhenFalse_ShouldThrowSecurityException()
        {
            Assert.Throws<SecurityException>(() => SecurityAssert.Assert(false));
        }

        [Fact]
        public void AssertHash_WhenEqual_ShouldDoNothing()
        {
            var a = new byte[] { 0, 1, 2, 3 };
            var b = new byte[] { 0, 1, 2, 3 };

            SecurityAssert.AssertHash(a, b);
        }

        [Fact]
        public void AssertHash_WhenAIsNull_ShouldThrowSecurityException()
        {
            var b = new byte[] { 0, 1, 2, 3 };

            Assert.Throws<SecurityException>(() => SecurityAssert.AssertHash(null, b));
        }
        [Fact]
        public void AssertHash_WhenBIsNull_ShouldThrowSecurityException()
        {
            var a = new byte[] { 0, 1, 2, 3 };

            Assert.Throws<SecurityException>(() => SecurityAssert.AssertHash(a, null));
        }

        [Fact]
        public void AssertHash_WhenLengthIsDifferent_ShouldThrowSecurityException()
        {
            var a = new byte[] { 0, 1, 2, 3 };
            var b = new byte[] { 0, 1, 2 };

            Assert.Throws<SecurityException>(() => SecurityAssert.AssertHash(a, b));
        }

        [Fact]
        public void AssertHash_WhenValuesAreDifferent_ShouldThrowSecurityException()
        {
            var a = new byte[] { 0, 1, 2, 3 };
            var b = new byte[] { 0, 1, 2, 4 };

            Assert.Throws<SecurityException>(() => SecurityAssert.AssertHash(a, b));
        }


        [Fact]
        public void AssertBuffer_WhenValid_ShouldDoNothing()
        {
            var a = new byte[] { 0, 1, 2, 3 };

            SecurityAssert.AssertBuffer(a, 0, a.Length);
            SecurityAssert.AssertBuffer(a, 3, 1);
            SecurityAssert.AssertBuffer(a, 1, 3);
        }
        [Fact]
        public void AssertBuffer_WhenBufferIsNull_ShouldThrowSecurityException()
        {
            Assert.Throws<SecurityException>(() => SecurityAssert.AssertBuffer(null, 0, 0));
        }
        [Fact]
        public void AssertBuffer_WhenOffsetIsNegative_ShouldThrowSecurityException()
        {
            var a = new byte[] { 0, 1, 2, 3 };

            Assert.Throws<SecurityException>(() => SecurityAssert.AssertBuffer(a, -1, 0));
        }
        [Fact]
        public void AssertBuffer_WhenLengthIsNegative_ShouldThrowSecurityException()
        {
            var a = new byte[] { 0, 1, 2, 3 };

            Assert.Throws<SecurityException>(() => SecurityAssert.AssertBuffer(a, 0, -1));
        }
        [Fact]
        public void AssertBuffer_WhenOverflow_ShouldThrowSecurityException()
        {
            var a = new byte[] { 0, 1, 2, 3 };

            Assert.Throws<SecurityException>(() => SecurityAssert.AssertBuffer(a, 3, 3));
        }
    }
}
