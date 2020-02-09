using System;
using System.IO;
using System.Text;
using Crypto.Core.Hashing;
using Crypto.Utils;
using Xunit;

namespace Crypto.SHA.Tests
{
    public class SHA256DigestTests
    {
        [Fact]
        public void NoInput_CorrectOutput()
        {
            var digest = new SHA256Digest(SHA256Digest.Mode.SHA256);

            var result = digest.DigestBuffer();

            AssertSHA256("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", result);
        }

        [Fact]
        public void SimpleString_CorrectOutput()
        {
            var digest = new SHA256Digest(SHA256Digest.Mode.SHA256);

            var buffer = new byte[] { 0x24 };
            digest.Update(buffer, 0, buffer.Length);

            var result = digest.DigestBuffer();

            AssertSHA256("09fc96082d34c2dfc1295d92073b5ea1dc8ef8da95f14dfded011ffb96d3e54b", result);
        }

        [Fact]
        public void String_CorrectOutput()
        {
            var digest = new SHA256Digest(SHA256Digest.Mode.SHA256);

            var buffer = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");
            digest.Update(buffer, 0, buffer.Length);

            var result = digest.DigestBuffer();

            AssertSHA256("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592", result);
        }

        [Fact]
        public void Clone_SeperateStateFromOriginal()
        {
            var digest = new SHA256Digest(SHA256Digest.Mode.SHA256);
            var buffer = Encoding.UTF8.GetBytes("The quick brown fox jumps");
            digest.Update(buffer, 0, buffer.Length);

            var digest2 = digest.Clone();
            buffer = Encoding.UTF8.GetBytes(" over the lazy dog");
            digest2.Update(buffer, 0, buffer.Length);

            var result1 = digest.DigestBuffer();
            var result2 = digest2.DigestBuffer();

            AssertSHA256("8df831769cd51e4f57808343603e97c1ea44fcab46bb595a5000b9ad1d03bd70", result1);
            AssertSHA256("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592", result2);
        }

        [Fact]
        public void NISTShortVectors_CorrectOutput()
        {
            RunNIST("SHA256ShortMsg.dat");
        }

        [Fact]
        public void NISTLongVectors_CorrectOutput()
        {
            RunNIST("SHA256LongMsg.dat");
        }

        private void RunNIST(string file)
        {
            var lines = File.ReadAllLines("TestVectors/" + file);

            for (var i = 0; i < lines.Length; i += 4)
            {
                var digest = new SHA256Digest(SHA256Digest.Mode.SHA256);

                var len = int.Parse(lines[i].Substring(6)) / 8;
                var msg = HexConverter.FromHex(lines[i + 1].Substring(6));
                var expectedHash = lines[i + 2].Substring(5);

                digest.Update(msg, 0, len);
                var hash = digest.DigestBuffer();

                AssertSHA256(expectedHash, hash);
            }
        }

        private void AssertSHA256(string expected, byte[] actual)
        {
            Assert.NotNull(actual);
            Assert.Equal(32, actual.Length);

            var expectedBuffer = HexConverter.FromHex(expected);

            Console.WriteLine("Expecting : {0}", expected);
            Console.WriteLine("Actual    : {0}", HexConverter.ToHex(actual));

            Assert.Equal(expectedBuffer, actual);
        }
    }
}
