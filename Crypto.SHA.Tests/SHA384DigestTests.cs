using System;
using System.IO;
using System.Text;
using Crypto.Core.Hashing;
using Crypto.Utils;
using Xunit;

namespace Crypto.SHA.Tests
{
    public class SHA384DigestTests
    {
        [Fact]
        public void NoInput_CorrectOutput()
        {
            var digest = new SHA512Digest(SHA512Digest.Mode.SHA384);

            var result = digest.DigestBuffer();

            AssertSHA384("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b", result);
        }

        [Fact]
        public void SimpleString_CorrectOutput()
        {
            var digest = new SHA512Digest(SHA512Digest.Mode.SHA384);

            var buffer = new byte[] { 0x24 };
            digest.Update(buffer, 0, buffer.Length);

            var result = digest.DigestBuffer();

            AssertSHA384("b1583f4b2e1bf53fc31e9dfb8e8d945a62955da709f280a9066aa8f31ef688d65e0e9816a5f1f11363b3898820bd1576", result);
        }

        [Fact]
        public void String_CorrectOutput()
        {
            var digest = new SHA512Digest(SHA512Digest.Mode.SHA384);

            var buffer = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");
            digest.Update(buffer, 0, buffer.Length);

            var result = digest.DigestBuffer();

            AssertSHA384("ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1", result);
        }

        [Fact]
        public void Clone_SeperateStateFromOriginal()
        {
            var digest = new SHA512Digest(SHA512Digest.Mode.SHA384);
            var buffer = Encoding.UTF8.GetBytes("The quick brown fox jumps");
            digest.Update(buffer, 0, buffer.Length);

            var digest2 = digest.Clone();
            buffer = Encoding.UTF8.GetBytes(" over the lazy dog");
            digest2.Update(buffer, 0, buffer.Length);

            var result1 = digest.DigestBuffer();
            var result2 = digest2.DigestBuffer();

            AssertSHA384("17ab2a4374f66611b44d072223392aac47619917f67c563be63506a2445438dac1f08aff2289b6306c63015e17f6d756", result1);
            AssertSHA384("ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1", result2);
        }

        [Fact]
        public void NISTShortVectors_CorrectOutput()
        {
            RunNIST("SHA384ShortMsg.dat");
        }

        [Fact]
        public void NISTLongVectors_CorrectOutput()
        {
            RunNIST("SHA384LongMsg.dat");
        }

        private void RunNIST(string file)
        {
            var lines = File.ReadAllLines("TestVectors/" + file);

            for (var i = 0; i < lines.Length; i += 4)
            {
                var digest = new SHA512Digest(SHA512Digest.Mode.SHA384);

                var len = int.Parse(lines[i].Substring(6)) / 8;
                var msg = HexConverter.FromHex(lines[i + 1].Substring(6));
                var expectedHash = lines[i + 2].Substring(5);

                digest.Update(msg, 0, len);
                var hash = digest.DigestBuffer();

                AssertSHA384(expectedHash, hash);
            }
        }

        private void AssertSHA384(string expected, byte[] actual)
        {
            Assert.NotNull(actual);
            Assert.Equal(48, actual.Length);

            var expectedBuffer = HexConverter.FromHex(expected);

            Console.WriteLine("Expecting : {0}", expected);
            Console.WriteLine("Actual    : {0}", HexConverter.ToHex(actual));

            Assert.Equal(expectedBuffer, actual);
        }
    }
}
