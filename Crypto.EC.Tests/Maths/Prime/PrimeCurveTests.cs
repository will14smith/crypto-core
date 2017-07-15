using Crypto.EC.Maths;
using Crypto.EC.Maths.Prime;
using Xunit;

namespace Crypto.EC.Tests.Maths.Prime
{
    public class PrimeCurveTests
    {
        [Fact]
        public void TestAddition_Basic()
        {
            var field = new PrimeField(97);
            var curve = new Curve<PrimeValue>(field, field.Int(2), field.Int(3));

            var a = new Point<PrimeValue>(field.Int(3), field.Int(6));
            var b = new Point<PrimeValue>(field.Int(11), field.Int(17));

            var c = Point<PrimeValue>.Add(curve, a, b);

            Assert.Equal(field.Int(47), c.X);
            Assert.Equal(field.Int(79), c.Y);
        }

        [Fact]
        public void TestAddition_Same()
        {
            var field = new PrimeField(97);
            var curve = new Curve<PrimeValue>(field, field.Int(2), field.Int(3));

            var a = new Point<PrimeValue>(field.Int(59), field.Int(32));

            var c = Point<PrimeValue>.Add(curve, a, a);

            Assert.Equal(field.Int(80), c.X);
            Assert.Equal(field.Int(10), c.Y);
        }

        [Fact(Skip = "Not Implemented")]
        public void TestMultiplication_Zero()
        {
            // TODO infinty?
        }

        [Fact]
        public void TestMultiplication_One()
        {
            var field = new PrimeField(97);
            var curve = new Curve<PrimeValue>(field, field.Int(2), field.Int(3));

            var a = new Point<PrimeValue>(field.Int(3), field.Int(6));

            var c = Point<PrimeValue>.Multiply(curve, field.Int(1), a);

            Assert.Equal(field.Int(3), c.X);
            Assert.Equal(field.Int(6), c.Y);
        }

        [Fact]
        public void TestMultiplication_Double()
        {
            var field = new PrimeField(97);
            var curve = new Curve<PrimeValue>(field, field.Int(2), field.Int(3));

            var a = new Point<PrimeValue>(field.Int(3), field.Int(6));

            var c = Point<PrimeValue>.Multiply(curve, field.Int(2), a);

            Assert.Equal(field.Int(80), c.X);
            Assert.Equal(field.Int(10), c.Y);
        }

        [Fact]
        public void TestMultiplication_Three()
        {
            var field = new PrimeField(97);
            var curve = new Curve<PrimeValue>(field, field.Int(2), field.Int(3));

            var a = new Point<PrimeValue>(field.Int(3), field.Int(6));

            var c = Point<PrimeValue>.Multiply(curve, field.Int(3), a);

            Assert.Equal(field.Int(80), c.X);
            Assert.Equal(field.Int(87), c.Y);
        }
    }
}
