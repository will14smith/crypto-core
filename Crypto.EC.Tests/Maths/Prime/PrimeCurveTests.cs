using Crypto.EC.Maths;
using Crypto.EC.Maths.Prime;
using Crypto.EC.Maths.Real;
using Xunit;

namespace Crypto.EC.Tests.Maths.Prime
{
    public class PrimeRealCurveTests
    {
        [Fact]
        public void TestAddition_Basic()
        {
            var field = new PrimeField(97);
            var curve = new RealCurve(field, field.Value(2), field.Value(3));

            var a = new Point(field.Value(3), field.Value(6));
            var b = new Point(field.Value(11), field.Value(17));

            var c = Point.Add(curve, a, b)!;

            Assert.Equal(field.Value(47), c.X);
            Assert.Equal(field.Value(79), c.Y);
        }

        [Fact]
        public void TestAddition_Same()
        {
            var field = new PrimeField(97);
            var curve = new RealCurve(field, field.Value(2), field.Value(3));

            var a = new Point(field.Value(59), field.Value(32));

            var c = Point.Add(curve, a, a)!;

            Assert.Equal(field.Value(80), c.X);
            Assert.Equal(field.Value(10), c.Y);
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
            var curve = new RealCurve(field, field.Value(2), field.Value(3));

            var a = new Point(field.Value(3), field.Value(6));

            var c = Point.Multiply(curve, field.Value(1), a);

            Assert.Equal(field.Value(3), c.X);
            Assert.Equal(field.Value(6), c.Y);
        }

        [Fact]
        public void TestMultiplication_Double()
        {
            var field = new PrimeField(97);
            var curve = new RealCurve(field, field.Value(2), field.Value(3));

            var a = new Point(field.Value(3), field.Value(6));

            var c = Point.Multiply(curve, field.Value(2), a);

            Assert.Equal(field.Value(80), c.X);
            Assert.Equal(field.Value(10), c.Y);
        }

        [Fact]
        public void TestMultiplication_Three()
        {
            var field = new PrimeField(97);
            var curve = new RealCurve(field, field.Value(2), field.Value(3));

            var a = new Point(field.Value(3), field.Value(6));

            var c = Point.Multiply(curve, field.Value(3), a);

            Assert.Equal(field.Value(80), c.X);
            Assert.Equal(field.Value(87), c.Y);
        }
    }
}
