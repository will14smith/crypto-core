using System;
using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace Crypto.Utils.Tests
{
    public class HexConverterTests
    {
        public static IEnumerable<object[]> TestCases => new[]
        {
            new object[] {"", new byte[] { }},
            new object[] {"0a", new byte[] { 10 }},
            new object[] {"10", new byte[] { 16 } },
            new object[] {"0110", new byte[] { 1, 16 } },
        };

        [Theory]
        [MemberData(nameof(TestCases))]
        public void FromHex_Correct(string input, byte[] expected)
        {
            Assert.Equal(expected.ToArray(), HexConverter.FromHex(input).ToArray());
        }
        [Fact]
        public void FromHex_IncorrectLength_ShouldThrow()
        {
            Assert.ThrowsAny<Exception>(() => HexConverter.FromHex("1"));
        }


        [Theory]
        [MemberData(nameof(TestCases))]
        public void ToHex_Correct(string expected, byte[] input)
        {
            Assert.Equal(expected, HexConverter.ToHex(input));
        }
    }
}
