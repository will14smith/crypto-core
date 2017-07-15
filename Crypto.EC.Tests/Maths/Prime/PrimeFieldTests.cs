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

            Assert.Equal(field.Int(4), field.Add(field.Int(18), field.Int(9)));
        }
        [Fact]
        public void TestSubtraction()
        {
            var field = new PrimeField(23);

            Assert.Equal(field.Int(16), field.Sub(field.Int(7), field.Int(14)));
        }

        [Fact]
        public void TestMultiplication()
        {
            var field = new PrimeField(23);

            Assert.Equal(field.Int(5), field.Multiply(field.Int(4), field.Int(7)));
        }
        [Fact]
        public void TestNegation()
        {
            var field = new PrimeField(23);

            Assert.Equal(field.Int(18), field.Negate(field.Int(5)));
        }
        [Fact]
        public void TestAdditiveInverse()
        {
            var field = new PrimeField(23);

            Assert.Equal(field.Int(0), field.Add(field.Int(5), field.Int(-5)));
        }
        [Fact]
        public void TestMultiplicativeInverse()
        {
            var field = new PrimeField(23);

            Assert.Equal(field.Int(18), field.Divide(field.Int(1), field.Int(9)));
        }
    }
}
