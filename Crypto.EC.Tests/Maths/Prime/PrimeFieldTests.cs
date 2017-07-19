using Crypto.EC.Maths.Prime;
using Xunit;

namespace Crypto.EC.Tests.Maths.Prime
{
    public class PrimeFieldTests
    {
        [Fact]
        public void TestAddition()
        {
            var field = new PrimeField(23);

            Assert.Equal(field.Value(4), field.Add(field.Value(18), field.Value(9)));
        }
        [Fact]
        public void TestSubtraction()
        {
            var field = new PrimeField(23);

            Assert.Equal(field.Value(16), field.Sub(field.Value(7), field.Value(14)));
        }

        [Fact]
        public void TestMultiplication()
        {
            var field = new PrimeField(23);

            Assert.Equal(field.Value(5), field.Multiply(field.Value(4), field.Value(7)));
        }
        [Fact]
        public void TestNegation()
        {
            var field = new PrimeField(23);

            Assert.Equal(field.Value(18), field.Negate(field.Value(5)));
        }
        [Fact]
        public void TestAdditiveInverse()
        {
            var field = new PrimeField(23);

            Assert.Equal(field.Value(0), field.Add(field.Value(5), field.Value(-5)));
        }
        [Fact]
        public void TestMultiplicativeInverse()
        {
            var field = new PrimeField(23);

            Assert.Equal(field.Value(18), field.Divide(field.Value(1), field.Value(9)));
        }
    }
}
