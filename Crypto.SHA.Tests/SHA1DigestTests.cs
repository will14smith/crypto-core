using System;
using System.IO;
using System.Text;
using Crypto.Utils;
using Xunit;

namespace Crypto.SHA.Tests
{
    public class SHA1DigestTests
    {
        [Fact]
        public void NoInput_CorrectOutput()
        {
            var digest = new SHA1Digest();

            var result = digest.Digest();

            AssertSHA1("da39a3ee5e6b4b0d3255bfef95601890afd80709", result);
        }

        [Fact]
        public void SimpleString_CorrectOutput()
        {
            var digest = new SHA1Digest();

            var buffer = new byte[] { 0x24 };
            digest.Update(buffer, 0, buffer.Length);

            var result = digest.Digest();

            AssertSHA1("3cdf2936da2fc556bfa533ab1eb59ce710ac80e5", result);
        }

        [Fact]
        public void StringInput_CorrectOutput()
        {
            var digest = new SHA1Digest();

            var buffer = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");
            digest.Update(buffer, 0, buffer.Length);

            var result = digest.Digest();

            AssertSHA1("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12", result);
        }

        [Fact]
        public void Clone_SeperateStateFromOriginal()
        {
            var digest = new SHA1Digest();
            var buffer = Encoding.UTF8.GetBytes("The quick brown fox jumps");
            digest.Update(buffer, 0, buffer.Length);

            var digest2 = digest.Clone();
            buffer = Encoding.UTF8.GetBytes(" over the lazy dog");
            digest2.Update(buffer, 0, buffer.Length);

            var result1 = digest.Digest();
            var result2 = digest2.Digest();

            AssertSHA1("743e27565bb39d4cf6cdf7b19450f94ef12b2206", result1);
            AssertSHA1("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12", result2);
        }


        [Fact]
        public void NISTShortVectors_CorrectOutput()
        {
            RunNIST("SHA1ShortMsg.dat");
        }

        [Fact]
        public void NISTLongVectors_CorrectOutput()
        {
            RunNIST("SHA1LongMsg.dat");
        }

        private static void RunNIST(string file)
        {
            var lines = File.ReadAllLines("TestVectors/" + file);

            for (var i = 0; i < lines.Length; i += 4)
            {
                var digest = new SHA1Digest();

                var len = int.Parse(lines[i].Substring(6)) / 8;
                var msg = HexConverter.FromHex(lines[i + 1].Substring(6));
                var expectedHash = lines[i + 2].Substring(5);

                digest.Update(msg, 0, len);
                var hash = digest.Digest();

                AssertSHA1(expectedHash, hash);
            }
        }

        private static void AssertSHA1(string expected, byte[] actual)
        {
            Assert.NotNull(actual);
            Assert.Equal(20, actual.Length);

            var expectedBuffer = HexConverter.FromHex(expected);

            Console.WriteLine("Expecting : {0}", expected);
            Console.WriteLine("Actual    : {0}", HexConverter.ToHex(actual));

            Assert.Equal(expectedBuffer, actual);
        }
    }
}
