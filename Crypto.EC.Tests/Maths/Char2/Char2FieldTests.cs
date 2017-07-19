using Crypto.EC.Maths.Char2;
using Xunit;

namespace Crypto.EC.Tests.Maths.Char2
{
    public class Char2FieldTests
    {
        [Fact]
        public void TestAddition()
        {
            var field = new Char2Field(4, 1);

            Assert.Equal(field.Value(0b0100), field.Add(field.Value(0b1101), field.Value(0b1001)));
        }
        [Fact]
        public void TestAdditiveIdentity()
        {
            var field = new Char2Field(4, 1);

            Assert.Equal(field.Value(0b0000), field.Add(field.Value(0b1101), field.Value(0b1101)));
        }
        [Fact]
        public void TestSubtraction()
        {
            var field = new Char2Field(4, 1);

            Assert.Equal(field.Value(0b1001), field.Sub(field.Value(0b1101), field.Value(0b0100)));
        }

        [Fact]
        public void TestNegation()
        {
            var field = new Char2Field(4, 1);

            Assert.Equal(field.Value(0b1101), field.Negate(field.Value(0b1101)));
        }

        [Fact]
        public void TestMultiplication()
        {
            var field = new Char2Field(4, 1);

            Assert.Equal(field.Value(0b0101), field.Multiply(field.Value(0b1101), field.Value(0b0111)));
        }
        [Fact]
        public void TestMultiplicativeInverse()
        {
            var field = new Char2Field(4, 1);

            Assert.Equal(field.Value(0b0100), field.Divide(field.Value(0b0001), field.Value(0b1101)));
        }
    }
}
