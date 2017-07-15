using System.Collections;
using System.Security;
using Xunit;

namespace Crypto.Utils.Tests
{
    public class BitArrayExtensionsTests
    {
        [Fact]
        public void GetByte_Null_FailsAssertion()
        {
            Assert.Throws<SecurityException>(() => BitArrayExtensions.GetByte(null, 0));
        }

        [Fact]
        public void GetByte_PartialByte()
        {
            var arr = new BitArray(3);
            arr.Set(1, true);

            var result = arr.GetByte(0);

            Assert.Equal(2, result);
        }

        [Fact]
        public void GetByte_PartialByteWithOffset()
        {
            var arr = new BitArray(3);
            arr.Set(1, true);

            var result = arr.GetByte(1);

            Assert.Equal(1, result);
        }

        [Fact]
        public void GetBytes_Null_FailsAssertion()
        {
            Assert.Throws<SecurityException>(() => BitArrayExtensions.GetBytes(null, 0, 0));
        }
        [Fact]
        public void GetBytes_OutOfRange_FailsAssertion()
        {
            var arr = new BitArray(3);

            Assert.Throws<SecurityException>(() => arr.GetBytes(8, 0));
            Assert.Throws<SecurityException>(() => arr.GetBytes(3, 1));
            Assert.Throws<SecurityException>(() => arr.GetBytes(0, 2));
        }

        [Fact]
        public void GetBytes_MultipleFull()
        {
            var arr = new BitArray(new byte[] { 1, 2, 3, 4 });

            var result = arr.GetBytes(8, 2);

            Assert.Equal(new byte[] { 2, 3 }, result);
        }

        [Fact]
        public void GetBytes_Partial()
        {
            var arr = new BitArray(3);
            arr.Set(1, true);

            var result = arr.GetBytes(0, 1);

            Assert.Equal(new byte[] { 2 }, result);
        }

        [Fact]
        public void ToArray_Null_FailsAssertion()
        {
            Assert.Throws<SecurityException>(() => BitArrayExtensions.ToArray(null));
        }

        [Fact]
        public void ToArray_Partial()
        {
            var arr = new BitArray(11);
            arr.Set(1, true);

            var result = arr.ToArray();

            Assert.Equal(new byte[] { 2, 0 }, result);
        }
    }
}
