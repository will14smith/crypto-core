using System;
using System.IO;
using System.Text;
using Crypto.Utils;
using Xunit;

namespace Crypto.SHA.Tests
{
    public class SHA224DigestTests
    {
        [Fact]
        public void NoInput_CorrectOutput()
        {
            var digest = new SHA256Digest(SHA256Digest.Mode.SHA224);

            var result = digest.Digest();

            AssertSHA224("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f", result);
        }

        [Fact]
        public void SimpleString_CorrectOutput()
        {
            var digest = new SHA256Digest(SHA256Digest.Mode.SHA224);

            var buffer = new byte[] { 0x24 };
            digest.Update(buffer);

            var result = digest.Digest();

            AssertSHA224("23fa1e672a6c2acdc4d7bfae713e0c9337ba057b5d5ace2685b59321", result);
        }

        [Fact]
        public void String_CorrectOutput()
        {
            var digest = new SHA256Digest(SHA256Digest.Mode.SHA224);

            var buffer = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");
            digest.Update(buffer);

            var result = digest.Digest();

            AssertSHA224("730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525", result);
        }

        [Fact]
        public void Clone_SeperateStateFromOriginal()
        {
            var digest = new SHA256Digest(SHA256Digest.Mode.SHA224);
            var buffer = Encoding.UTF8.GetBytes("The quick brown fox jumps");
            digest.Update(buffer);

            var digest2 = digest.Clone();
            buffer = Encoding.UTF8.GetBytes(" over the lazy dog");
            digest2.Update(buffer);

            var result1 = digest.Digest();
            var result2 = digest2.Digest();

            AssertSHA224("51e20e8548cc6b25a948cbda204d8dd970246d31203f97e8effaf368", result1);
            AssertSHA224("730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525", result2);
        }

        [Fact]
        public void NISTShortVectors_CorrectOutput()
        {
            RunNIST("SHA224ShortMsg.dat");
        }

        [Fact]
        public void NISTLongVectors_CorrectOutput()
        {
            RunNIST("SHA224LongMsg.dat");
        }

        private void RunNIST(string file)
        {
            var lines = File.ReadAllLines("TestVectors/" + file);

            for (var i = 0; i < lines.Length; i += 4)
            {
                var digest = new SHA256Digest(SHA256Digest.Mode.SHA224);

                var len = int.Parse(lines[i].Substring(6)) / 8;
                var msg = HexConverter.FromHex(lines[i + 1].Substring(6));
                var expectedHash = lines[i + 2].Substring(5);

                digest.Update(msg.Slice(0, len));
                var hash = digest.Digest();

                AssertSHA224(expectedHash, hash);
            }
        }

        private void AssertSHA224(string expected, ReadOnlySpan<byte> actual)
        {
            Assert.Equal(28, actual.Length);

            var expectedBuffer = HexConverter.FromHex(expected);

            Console.WriteLine("Expecting : {0}", expected);
            Console.WriteLine("Actual    : {0}", HexConverter.ToHex(actual));

            Assert.Equal(expectedBuffer.ToArray(), actual.ToArray());
        }
    }
}
