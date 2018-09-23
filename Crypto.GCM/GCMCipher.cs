using System;
using Crypto.Core.Encryption;
using Crypto.Core.Encryption.BlockModes;
using Crypto.Core.Encryption.Parameters;
using Crypto.Core.Hashing;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.GCM
{
    public class GCMCipher : IAEADBlockCipher
    {
        private long _ivSize;
        private long _aSize;
        private long _cSize;

        private byte[] _h;
        private byte[] _j0;
        private IDigest _tagHash;

        public GCMCipher(IBlockCipher cipher)
        {
            SecurityAssert.Assert(cipher.BlockLength == 16);
            SecurityAssert.Assert(cipher.KeySize >= 16);

            Cipher = cipher;
            _buffer = new byte[BlockLength];
        }

        public IBlockCipher Cipher { get; }

        public int BlockLength => Cipher.BlockLength;
        public int KeySize => Cipher.KeySize;
        public int TagLength => 16;

        public void Init(ICipherParameters parameters)
        {
            // setup AAD
            var aadParam = parameters as AADParameter;
            SecurityAssert.NotNull(aadParam);

            var a = aadParam.AAD;
            _aSize = a.Length * 8;

            // setup IV
            var ivParam = aadParam.Parameters as IVParameter;
            SecurityAssert.NotNull(ivParam);

            var iv = ivParam.IV;
            _ivSize = iv.Length * 8;

            // setup cipher
            Cipher.Init(ivParam.Parameters);

            // setup H subkey
            _h = new byte[16];
            Cipher.EncryptBlock(new byte[16], _h);

            // setup tag hash
            _tagHash = new GHash(_h);
            _tagHash.Update(a.Span);
            var tagAADPaddingLength = 16 - a.Length % 16;
            _tagHash.Update(new byte[tagAADPaddingLength]);

            // setup pre-counter block
            if (iv.Length == 12)
            {
                // IV || 0^31 ||1

                _j0 = new byte[16];
                iv.Span.CopyTo(_j0);
                _j0[15] = 1;
            }
            else
            {
                // GHASH_H(IV || 0^(s+64) || [len(IV)])

                var j0PaddingLength = 8 + (16 - iv.Length % 16) % 16;

                var j0Hash = new GHash(_h);
                j0Hash.Update(iv.Span);
                j0Hash.Update(new byte[j0PaddingLength]);
                j0Hash.Update(EndianBitConverter.Big.GetBytes(_ivSize));

                _j0 = j0Hash.Digest().ToArray();
            }

            _ctr = new CTRBlockCipher(Cipher);
            _ctr.Init(new IVParameter(null, _j0));
            _ctr.Inc();

            _cSize = 0;
        }

        private readonly byte[] _buffer;
        private int _bufferOffset;
        private CTRBlockCipher _ctr;

        public AEADResult Encrypt(ReadOnlySpan<byte> input, Span<byte> output)
        {
            foreach (var t in input)
            {
                _buffer[_bufferOffset++] = t;

                if (_bufferOffset == BlockLength)
                {
                    output = EncryptBlock(output);
                }
            }

            return new AEADResult(new ReadOnlySpan<byte>(), output);
        }

        private Span<byte> EncryptBlock(Span<byte> output)
        {
            var bufferLength = _bufferOffset;

            // encrypt block
            var ciphertext = new byte[BlockLength];
            _ctr.EncryptBlock(_buffer, ciphertext);

            // copy to output
            ciphertext.AsSpan().Slice(0, bufferLength).CopyTo(output);

            // update tag hash
            _tagHash.Update(output.Slice(0, bufferLength));
            _cSize += bufferLength * 8;

            // clear buffer
            _bufferOffset = 0;
            Array.Clear(_buffer, 0, BlockLength);

            return output.Slice(bufferLength);
        }

        public AEADResult EncryptFinal(AEADResult previousResult)
        {
            var output = previousResult.RemainingOutput; 

            if (_bufferOffset != 0)
            {
                output = EncryptBlock(output);
            }

            var tagCiphertextPaddingLength = (16 - (int)(_cSize / 8) % 16) % 16;
            _tagHash.Update(new byte[tagCiphertextPaddingLength]);
            _tagHash.Update(EndianBitConverter.Big.GetBytes(_aSize));
            _tagHash.Update(EndianBitConverter.Big.GetBytes(_cSize));

            var ctr = new CTRBlockCipher(Cipher);
            ctr.Init(new IVParameter(null, _j0));

            ctr.EncryptBlock(_tagHash.Digest(), output);

            return new AEADResult(previousResult.RemainingInput, output);
        }

        public AEADResult Decrypt(ReadOnlySpan<byte> input, Span<byte> output)
        {
            // Don't consume what could be the tag
            var length = input.Length - TagLength;

            // TODO round length up to BlockLength
            SecurityAssert.AssertInputOutputBuffers(input, output, length);

            for (var index = 0; index < length; index++)
            {
                var t = input[index];
                _buffer[_bufferOffset++] = t;

                if (_bufferOffset == BlockLength)
                {
                    output = DecryptBlock(output);
                }
            }

            return new AEADResult(input.Slice(length), output);
        }

        private Span<byte> DecryptBlock(Span<byte> output)
        {
            var bufferLength = _bufferOffset;

            // encrypt block
            var plaintext = new byte[BlockLength];
            _ctr.DecryptBlock(_buffer, plaintext);

            // copy to output
            plaintext.AsSpan().Slice(0, bufferLength).CopyTo(output);
                
            // update tag hash
            _tagHash.Update(_buffer.AsSpan().Slice(0, bufferLength));
            _cSize += bufferLength * 8;

            // clear buffer
            _bufferOffset = 0;
            Array.Clear(_buffer, 0, BlockLength);

            return output.Slice(bufferLength);
        }

        public AEADResult DecryptFinal(AEADResult previousResult)
        {
            // TODO SecurityAssert.AssertBuffer(input, inputOffset, _bufferOffset + TagLength);
            // TODO SecurityAssert.AssertBuffer(output, outputOffset, _bufferOffset);

            // Consume everything but the Tag
            previousResult = this.Decrypt(previousResult);
            var input = previousResult.RemainingInput;
            var output = previousResult.RemainingOutput;
            
            if (_bufferOffset != 0)
            {
                output = DecryptBlock(output);
            }

            var tagCiphertextPaddingLength = (16 - (int)(_cSize / 8) % 16) % 16;
            _tagHash.Update(new byte[tagCiphertextPaddingLength]);
            _tagHash.Update(EndianBitConverter.Big.GetBytes(_aSize));
            _tagHash.Update(EndianBitConverter.Big.GetBytes(_cSize));

            var tagCtr = new CTRBlockCipher(Cipher);
            tagCtr.Init(new IVParameter(null, _j0));

            var digest = _tagHash.Digest();
            var calculatedTag = new byte[16];
            tagCtr.EncryptBlock(digest, calculatedTag);

            var tag = input.Slice(0, TagLength);
            SecurityAssert.AssertHash(calculatedTag, tag);

            return new AEADResult(input.Slice(TagLength), output);
        }
    }
}
