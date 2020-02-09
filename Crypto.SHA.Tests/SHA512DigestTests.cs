using System;
using System.IO;
using System.Text;
using Crypto.Core.Hashing;
using Crypto.Utils;
using Xunit;

namespace Crypto.SHA.Tests
{
    public class SHA512DigestTests
    {
        [Fact]
        public void NoInput_CorrectOutput()
        {
            var digest = new SHA512Digest(SHA512Digest.Mode.SHA512);

            var result = digest.DigestBuffer();

            AssertSHA512("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", result);
        }

        [Fact]
        public void SimpleString_CorrectOutput()
        {
            var digest = new SHA512Digest(SHA512Digest.Mode.SHA512);

            var buffer = new byte[] { 0x24 };
            digest.Update(buffer);

            var result = digest.DigestBuffer();

            AssertSHA512("840cfc6285878464c36c9aa819d8373729eda14c3e701fd37afec1d5baa2893944c696fc4017a520abfbb1347b62e6b858211d3ea7c7dd26319601fde119c3b4", result);
        }

        [Fact]
        public void String_CorrectOutput()
        {
            var digest = new SHA512Digest(SHA512Digest.Mode.SHA512);

            var buffer = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");
            digest.Update(buffer);

            var result = digest.DigestBuffer();

            AssertSHA512("07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6", result);
        }
        
        [Fact]
        public void Clone_SeperateStateFromOriginal()
        {
            var digest = new SHA512Digest(SHA512Digest.Mode.SHA512);
            var buffer = Encoding.UTF8.GetBytes("The quick brown fox jumps");
            digest.Update(buffer);

            var digest2 = digest.Clone();
            buffer = Encoding.UTF8.GetBytes(" over the lazy dog");
            digest2.Update(buffer);

            var result1 = digest.DigestBuffer();
            var result2 = digest2.DigestBuffer();

            AssertSHA512("4b4c254dd0bc5c4a1a70900bc9eea84c852e11ac3d16f87f1d3aaff0478e46ee58c264d4aea58d2ce1b08e84bd7bbbf032e99521f60fcec637abdb243977dd7c", result1);
            AssertSHA512("07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6", result2);
        }

        [Fact]
        public void NISTShortVectors_CorrectOutput()
        {
            RunNIST("SHA512ShortMsg.dat");
        }

        [Fact]
        public void NISTLongVectors_CorrectOutput()
        {
            RunNIST("SHA512LongMsg.dat");
        }

        private void RunNIST(string file)
        {
            var lines = File.ReadAllLines("TestVectors/" + file);

            for (var i = 0; i < lines.Length; i += 4)
            {
                var digest = new SHA512Digest(SHA512Digest.Mode.SHA512);

                var len = int.Parse(lines[i].Substring(6)) / 8;
                var msg = HexConverter.FromHex(lines[i + 1].Substring(6));
                var expectedHash = lines[i + 2].Substring(5);

                digest.Update(msg.AsSpan(0, len));
                var hash = digest.DigestBuffer();

                AssertSHA512(expectedHash, hash);
            }
        }

        private void AssertSHA512(string expected, byte[] actual)
        {
            Assert.NotNull(actual);
            Assert.Equal(64, actual.Length);

            var expectedBuffer = HexConverter.FromHex(expected);

            Console.WriteLine("Expecting : {0}", expected);
            Console.WriteLine("Actual    : {0}", HexConverter.ToHex(actual));

            Assert.Equal(expectedBuffer, actual);
        }
    }
}
