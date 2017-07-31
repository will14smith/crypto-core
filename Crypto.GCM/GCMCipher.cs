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
            Cipher.EncryptBlock(new byte[16], 0, _h, 0);

            // setup tag hash
            _tagHash = new GHash(_h);
            _tagHash.Update(a, 0, a.Length);
            var tagAADPaddingLength = 16 - a.Length % 16;
            _tagHash.Update(new byte[tagAADPaddingLength], 0, tagAADPaddingLength);

            // setup pre-counter block
            if (iv.Length == 12)
            {
                // IV || 0^31 ||1

                _j0 = new byte[16];
                Array.Copy(iv, _j0, 12);
                _j0[15] = 1;
            }
            else
            {
                // GHASH_H(IV || 0^(s+64) || [len(IV)])

                var j0PaddingLength = 8 + (16 - iv.Length % 16) % 16;

                var j0Hash = new GHash(_h);
                j0Hash.Update(iv, 0, iv.Length);
                j0Hash.Update(new byte[j0PaddingLength], 0, j0PaddingLength);
                j0Hash.Update(EndianBitConverter.Big.GetBytes(_ivSize), 0, sizeof(long));

                _j0 = j0Hash.Digest();
            }

            _ctr = new CTRBlockCipher(Cipher);
            _ctr.Init(new IVParameter(null, _j0));
            _ctr.Inc();

            _cSize = 0;
        }

        private readonly byte[] _buffer;
        private int _bufferOffset;
        private CTRBlockCipher _ctr;

        public int Encrypt(byte[] input, int inputOffset, byte[] output, int outputOffset, int length)
        {
            var total = 0;

            for (var i = 0; i < length; i++)
            {
                _buffer[_bufferOffset++] = input[inputOffset + i];

                if (_bufferOffset == BlockLength)
                {
                    EncryptBlock(output, outputOffset);
                    outputOffset += BlockLength;
                    total += BlockLength;
                }
            }

            return total;
        }

        private void EncryptBlock(byte[] output, int outputOffset)
        {
            // encrypt block
            var ciphertext = new byte[BlockLength];
            _ctr.EncryptBlock(_buffer, 0, ciphertext, 0);

            // copy to output
            Array.Copy(ciphertext, 0, output, outputOffset, _bufferOffset);

            // update tag hash
            _tagHash.Update(output, outputOffset, _bufferOffset);
            _cSize += _bufferOffset * 8;

            // clear buffer
            _bufferOffset = 0;
            Array.Clear(_buffer, 0, BlockLength);
        }

        public int EncryptFinal(byte[] output, int offset, byte[] tag)
        {
            SecurityAssert.AssertBuffer(tag, 0, TagLength);

            var total = 0;

            if (_bufferOffset != 0)
            {
                total += _bufferOffset;

                EncryptBlock(output, offset);
            }

            var tagCiphertextPaddingLength = (16 - (int)(_cSize / 8) % 16) % 16;
            _tagHash.Update(new byte[tagCiphertextPaddingLength], 0, tagCiphertextPaddingLength);
            _tagHash.Update(EndianBitConverter.Big.GetBytes(_aSize), 0, sizeof(long));
            _tagHash.Update(EndianBitConverter.Big.GetBytes(_cSize), 0, sizeof(long));

            var ctr = new CTRBlockCipher(Cipher);
            ctr.Init(new IVParameter(null, _j0));

            ctr.EncryptBlock(_tagHash.Digest(), 0, tag, 0);

            return total;
        }

        public int Decrypt(byte[] input, int inputOffset, byte[] output, int outputOffset, int length)
        {
            SecurityAssert.AssertBuffer(input, inputOffset, length);
            // TODO round length up to BlockLength
            SecurityAssert.AssertBuffer(output, outputOffset, length);

            var total = 0;

            for (var i = 0; i < length; i++)
            {
                _buffer[_bufferOffset++] = input[inputOffset + i];

                if (_bufferOffset == BlockLength)
                {
                    DecryptBlock(output, outputOffset);
                    outputOffset += BlockLength;
                    total += BlockLength;
                }
            }

            return total;
        }

        private void DecryptBlock(byte[] output, int outputOffset)
        {
            // encrypt block
            var plaintext = new byte[BlockLength];
            _ctr.DecryptBlock(_buffer, 0, plaintext, 0);

            // copy to output
            Array.Copy(plaintext, 0, output, outputOffset, _bufferOffset);

            // update tag hash
            _tagHash.Update(_buffer, 0, _bufferOffset);
            _cSize += _bufferOffset * 8;

            // clear buffer
            _bufferOffset = 0;
            Array.Clear(_buffer, 0, BlockLength);
        }

        public int DecryptFinal(byte[] input, int inputOffset, byte[] output, int outputOffset)
        {
            SecurityAssert.AssertBuffer(input, inputOffset, _bufferOffset + TagLength);
            SecurityAssert.AssertBuffer(output, outputOffset, _bufferOffset);

            var total = 0;
            if (_bufferOffset != 0)
            {
                total += _bufferOffset;
                inputOffset += _bufferOffset;

                DecryptBlock(output, outputOffset);
            }

            var tagCiphertextPaddingLength = (16 - (int)(_cSize / 8) % 16) % 16;
            _tagHash.Update(new byte[tagCiphertextPaddingLength], 0, tagCiphertextPaddingLength);
            _tagHash.Update(EndianBitConverter.Big.GetBytes(_aSize), 0, sizeof(long));
            _tagHash.Update(EndianBitConverter.Big.GetBytes(_cSize), 0, sizeof(long));

            var tagCtr = new CTRBlockCipher(Cipher);
            tagCtr.Init(new IVParameter(null, _j0));

            var digest = _tagHash.Digest();
            var calculatedTag = new byte[16];
            tagCtr.EncryptBlock(digest, 0, calculatedTag, 0);

            var tag = new byte[16];
            Array.Copy(input, inputOffset, tag, 0, TagLength);

            SecurityAssert.AssertHash(calculatedTag, tag);

            return total;
        }
    }
}
