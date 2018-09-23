using System.Numerics;
using Crypto.Utils.IO;
using Xunit;

namespace Crypto.Utils.Tests
{
    public class BigIntegerExtensionsTests
    {
        [Theory]
        [InlineData("0", 1)]
        [InlineData("1", 1)]
        [InlineData("255", 1)]
        [InlineData("256", 2)]
        public void GetByteLength_Correct(string inputStr, int expectedLength)
        {
            var input = BigInteger.Parse(inputStr);

            var length = input.GetByteLength();

            Assert.Equal(expectedLength, length);
        }

        [Theory]
        [InlineData("0", 1)]
        [InlineData("1", 1)]
        [InlineData("255", 8)]
        [InlineData("256", 9)]
        public void GetBitLength_Correct(string inputStr, int expectedLength)
        {
            var input = BigInteger.Parse(inputStr);

            var length = input.GetBitLength();

            Assert.Equal(expectedLength, length);
        }

        [Theory]
        [InlineData("0", Endianness.BigEndian, new byte[] { })]
        [InlineData("0", Endianness.LittleEndian, new byte[] { })]
        [InlineData("1", Endianness.BigEndian, new byte[] { 1 })]
        [InlineData("1", Endianness.LittleEndian, new byte[] { 1 })]
        [InlineData("255", Endianness.BigEndian, new byte[] { 255 })]
        [InlineData("255", Endianness.LittleEndian, new byte[] { 255 })]
        [InlineData("256", Endianness.BigEndian, new byte[] { 1, 0 })]
        [InlineData("256", Endianness.LittleEndian, new byte[] { 0, 1 })]
        public void ToByteArray_Correct(string inputStr, Endianness endianness, byte[] expectedBytes)
        {
            var input = BigInteger.Parse(inputStr);

            var bytes = input.ToByteArray(endianness);

            Assert.Equal(HexConverter.ToHex(expectedBytes), HexConverter.ToHex(bytes));
        }

        [Theory]
        [InlineData("0", Endianness.BigEndian, new byte[] { })]
        [InlineData("0", Endianness.LittleEndian, new byte[] { })]
        [InlineData("1", Endianness.BigEndian, new byte[] { 1 })]
        [InlineData("1", Endianness.LittleEndian, new byte[] { 1 })]
        [InlineData("255", Endianness.BigEndian, new byte[] { 255 })]
        [InlineData("255", Endianness.LittleEndian, new byte[] { 255 })]
        [InlineData("256", Endianness.BigEndian, new byte[] { 1, 0 })]
        [InlineData("256", Endianness.LittleEndian, new byte[] { 0, 1 })]
        public void ToBigInteger_Correct(string expectedStr, Endianness endianness, byte[] input)
        {
            var bytes = input.ToBigInteger(endianness);

            Assert.Equal(BigInteger.Parse(expectedStr), bytes);
        }
    }
}

