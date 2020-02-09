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
            var curve = new RealCurve(intField, intField.Value(-7), intField.Value(10));

            var a = new Point(intField.Value(1), intField.Value(2));
            var b = new Point(intField.Value(3), intField.Value(4));

            var c = Point.Add(curve, a, b)!;

            Assert.Equal(intField.Value(-3), c.X);
            Assert.Equal(intField.Value(2), c.Y);
        }

        [Fact]
        public void TestAddition_Same()
        {
            var intField = new RealField();
            var curve = new RealCurve(intField, intField.Value(-7), intField.Value(10));

            var a = new Point(intField.Value(1), intField.Value(2));

            var c = Point.Add(curve, a, a)!;

            Assert.Equal(intField.Value(-1), c.X);
            Assert.Equal(intField.Value(-4), c.Y);
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
            var curve = new RealCurve(intField, intField.Value(-7), intField.Value(10));

            var a = new Point(intField.Value(1), intField.Value(2));

            var c = Point.Multiply(curve, intField.Value(1), a);

            Assert.Equal(intField.Value(1), c.X);
            Assert.Equal(intField.Value(2), c.Y);
        }

        [Fact]
        public void TestMultiplication_Double()
        {
            var intField = new RealField();
            var curve = new RealCurve(intField, intField.Value(-7), intField.Value(10));

            var a = new Point(intField.Value(1), intField.Value(2));

            var c = Point.Multiply(curve, intField.Value(2), a);

            Assert.Equal(intField.Value(-1), c.X);
            Assert.Equal(intField.Value(-4), c.Y);
        }

        [Fact]
        public void TestMultiplication_Three()
        {
            var intField = new RealField();
            var curve = new RealCurve(intField, intField.Value(-7), intField.Value(10));

            var a = new Point(intField.Value(1), intField.Value(2));

            var c = Point.Multiply(curve, intField.Value(3), a);

            Assert.Equal(intField.Value(9), c.X);
            Assert.Equal(intField.Value(-26), c.Y);
        }
    }
}
