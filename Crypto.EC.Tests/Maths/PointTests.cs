using Crypto.EC.Maths;
using Crypto.EC.Maths.Real;
using Xunit;

namespace Crypto.EC.Tests.Maths
{
    public class PointTests
    {
        [Fact]
        public void TestAddition_Basic()
        {
            var intField = new RealField();
            var curve = new Curve<RealValue>(intField, intField.Int(-7), intField.Int(10));

            var a = new Point<RealValue>(intField.Int(1), intField.Int(2));
            var b = new Point<RealValue>(intField.Int(3), intField.Int(4));

            var c = Point<RealValue>.Add(curve, a, b);

            Assert.Equal(intField.Int(-3), c.X);
            Assert.Equal(intField.Int(2), c.Y);
        }

        [Fact]
        public void TestAddition_Same()
        {
            var intField = new RealField();
            var curve = new Curve<RealValue>(intField, intField.Int(-7), intField.Int(10));

            var a = new Point<RealValue>(intField.Int(1), intField.Int(2));

            var c = Point<RealValue>.Add(curve, a, a);

            Assert.Equal(intField.Int(-1), c.X);
            Assert.Equal(intField.Int(-4), c.Y);
        }

        [Fact(Skip = "Not Implemented")]
        public void TestMultiplication_Zero()
        {
            // TODO infinty?
        }

        [Fact]
        public void TestMultiplication_One()
        {
            var intField = new RealField();
            var curve = new Curve<RealValue>(intField, intField.Int(-7), intField.Int(10));

            var a = new Point<RealValue>(intField.Int(1), intField.Int(2));

            var c = Point<RealValue>.Multiply(curve, intField.Int(1), a);

            Assert.Equal(intField.Int(1), c.X);
            Assert.Equal(intField.Int(2), c.Y);
        }

        [Fact]
        public void TestMultiplication_Double()
        {
            var intField = new RealField();
            var curve = new Curve<RealValue>(intField, intField.Int(-7), intField.Int(10));

            var a = new Point<RealValue>(intField.Int(1), intField.Int(2));

            var c = Point<RealValue>.Multiply(curve, intField.Int(2), a);

            Assert.Equal(intField.Int(-1), c.X);
            Assert.Equal(intField.Int(-4), c.Y);
        }

        [Fact]
        public void TestMultiplication_Three()
        {
            var intField = new RealField();
            var curve = new Curve<RealValue>(intField, intField.Int(-7), intField.Int(10));

            var a = new Point<RealValue>(intField.Int(1), intField.Int(2));

            var c = Point<RealValue>.Multiply(curve, intField.Int(3), a);

            Assert.Equal(intField.Int(9), c.X);
            Assert.Equal(intField.Int(-26), c.Y);
        }
    }
}
