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

        public int Encrypt(ReadOnlySpan<byte> input, Span<byte> output)
        {
            var total = 0;

            var outputOffset = 0;
            foreach (var t in input)
            {
                _buffer[_bufferOffset++] = t;

                if (_bufferOffset == BlockLength)
                {
                    EncryptBlock(output.Slice(outputOffset, BlockLength));
                    outputOffset += BlockLength;
                    total += BlockLength;
                }
            }

            return total;
        }

        private void EncryptBlock(Span<byte> output)
        {
            // encrypt block
            var ciphertext = new byte[BlockLength];
            _ctr.EncryptBlock(_buffer, ciphertext);

            // copy to output
            ciphertext.AsSpan().Slice(0, _bufferOffset).CopyTo(output);

            // update tag hash
            _tagHash.Update(output.Slice(0, _bufferOffset));
            _cSize += _bufferOffset * 8;

            // clear buffer
            _bufferOffset = 0;
            Array.Clear(_buffer, 0, BlockLength);
        }

        public int EncryptFinal(Span<byte> output, Span<byte> tag)
        {
            // SecurityAssert.AssertBuffer(tag, 0, TagLength);

            var total = 0;

            if (_bufferOffset != 0)
            {
                total += _bufferOffset;

                EncryptBlock(output);
            }

            var tagCiphertextPaddingLength = (16 - (int)(_cSize / 8) % 16) % 16;
            _tagHash.Update(new byte[tagCiphertextPaddingLength]);
            _tagHash.Update(EndianBitConverter.Big.GetBytes(_aSize));
            _tagHash.Update(EndianBitConverter.Big.GetBytes(_cSize));

            var ctr = new CTRBlockCipher(Cipher);
            ctr.Init(new IVParameter(null, _j0));

            ctr.EncryptBlock(_tagHash.Digest(), tag);

            return total;
        }

        public int Decrypt(ReadOnlySpan<byte> input, Span<byte> output)
        {
            // TODO round length up to BlockLength
            SecurityAssert.AssertInputOutputBuffers(input, output);

            var total = 0;
            var outputOffset = 0;

            // TODO this could be more efficient
            foreach (var t in input)
            {
                _buffer[_bufferOffset++] = t;

                if (_bufferOffset == BlockLength)
                {
                    DecryptBlock(output.Slice(outputOffset));
                    outputOffset += BlockLength;
                    total += BlockLength;
                }
            }

            return total;
        }

        private void DecryptBlock(Span<byte> output)
        {
            // encrypt block
            var plaintext = new byte[BlockLength];
            _ctr.DecryptBlock(_buffer, plaintext);

            // copy to output
            plaintext.AsSpan().Slice(0, _bufferOffset).CopyTo(output);
                
            // update tag hash
            _tagHash.Update(_buffer.AsSpan().Slice(0, _bufferOffset));
            _cSize += _bufferOffset * 8;

            // clear buffer
            _bufferOffset = 0;
            Array.Clear(_buffer, 0, BlockLength);
        }

        public int DecryptFinal(ReadOnlySpan<byte> input, Span<byte> output)
        {
            // TODO SecurityAssert.AssertBuffer(input, inputOffset, _bufferOffset + TagLength);
            // TODO SecurityAssert.AssertBuffer(output, outputOffset, _bufferOffset);

            var total = 0;
            var inputOffset = 0;
            if (_bufferOffset != 0)
            {
                total += _bufferOffset;
                inputOffset += _bufferOffset;

                DecryptBlock(output);
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

            var tag = new byte[16];
            input.Slice(inputOffset, TagLength).CopyTo(tag);
            
            SecurityAssert.AssertHash(calculatedTag, tag);

            return total;
        }
    }
}
