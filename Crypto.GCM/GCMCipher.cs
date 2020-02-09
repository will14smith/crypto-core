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
        private readonly IBlockCipher _cipher;
        private State? _state;

        public GCMCipher(IBlockCipher cipher)
        {
            SecurityAssert.Assert(cipher.BlockLength == 16);
            SecurityAssert.Assert(cipher.KeySize >= 16);

            _cipher = cipher;
        }

        public int BlockLength => _cipher.BlockLength;
        public int KeySize => _cipher.KeySize;
        public int TagLength => 16;

        public void Init(ICipherParameters parameters)
        {
            // setup AAD
            var aadParam = parameters as AADParameter;
            SecurityAssert.NotNull(aadParam);
            
            var a = aadParam!.AAD;
            var aSize = a.Length * 8;

            // setup IV
            var ivParam = aadParam!.Parameters as IVParameter;
            SecurityAssert.NotNull(ivParam);
            
            var iv = ivParam!.IV;
            var ivSize = iv.Length * 8;

            // setup cipher
            _cipher.Init(ivParam!.Parameters);

            // setup H subkey
            var h = new byte[16];
            _cipher.EncryptBlock(new byte[16], 0, h, 0);

            // setup tag hash
            var tagHash = new GHash(h);
            tagHash.Update(a, 0, a.Length);
            var tagAADPaddingLength = 16 - a.Length % 16;
            tagHash.Update(new byte[tagAADPaddingLength], 0, tagAADPaddingLength);
            
            // setup pre-counter block
            byte[] j0;
            if (iv.Length == 12)
            {
                // IV || 0^31 ||1
            
                j0 = new byte[16];
                Array.Copy(iv, j0, 12);
                j0[15] = 1;
            }
            else
            {
                // GHASH_H(IV || 0^(s+64) || [len(IV)])
            
                var j0PaddingLength = 8 + (16 - iv.Length % 16) % 16;
            
                var j0Hash = new GHash(h);
                j0Hash.Update(iv, 0, iv.Length);
                j0Hash.Update(new byte[j0PaddingLength], 0, j0PaddingLength);
                j0Hash.Update(EndianBitConverter.Big.GetBytes(ivSize), 0, sizeof(long));
            
                j0 = j0Hash.Digest();
            }
            
            var ctr = new CTRBlockCipher(_cipher);
            ctr.Init(new IVParameter(j0));
            ctr.Inc();
            
            _state = new State(aSize, BlockLength, TagLength, j0, tagHash, ctr, _cipher);
        }
        
        public int Encrypt(byte[] input, int inputOffset, byte[] output, int outputOffset, int length)
        {
            if(_state == null) throw new InvalidOperationException("GCM is not initialized");
            return _state.Encrypt(input, inputOffset, output, outputOffset, length);
        }

       
        public int EncryptFinal(byte[] output, int offset, byte[] tag)
        {
            if(_state == null) throw new InvalidOperationException("GCM is not initialized");
            return _state.EncryptFinal(output, offset, tag);
        }

        public int Decrypt(byte[] input, int inputOffset, byte[] output, int outputOffset, int length)
        {
            if(_state == null) throw new InvalidOperationException("GCM is not initialized");
            return _state.Decrypt(input, inputOffset, output, outputOffset, length);
        }
        
        public int DecryptFinal(byte[] input, int inputOffset, byte[] output, int outputOffset)
        {
            if(_state == null) throw new InvalidOperationException("GCM is not initialized");
            return _state.DecryptFinal(input, inputOffset, output, outputOffset);
        }
        
        private class State
        {
            private readonly long _aSize;
            private long _cSize;
            private readonly int _tagSize;

            private readonly byte[] _j0;
            private readonly IDigest _tagHash;

            private readonly byte[] _buffer;
            private readonly int _blockSize;
            private int _bufferOffset;
            private readonly CTRBlockCipher _ctr;
            private readonly IBlockCipher _cipher;

            public State(long aSize, int blockSize, int tagSize, byte[] j0, IDigest tagHash, CTRBlockCipher ctr, IBlockCipher cipher)
            {
                _aSize = aSize;

                _j0 = j0;
                _tagHash = tagHash;
                _ctr = ctr;
                _cipher = cipher;

                _buffer = new byte[blockSize];
                _blockSize = blockSize;
                _tagSize = tagSize;
            }
            
            public int Encrypt(byte[] input, int inputOffset, byte[] output, int outputOffset, int length)
            {
                var total = 0;

                for (var i = 0; i < length; i++)
                {
                    _buffer[_bufferOffset++] = input[inputOffset + i];

                    if (_bufferOffset == _blockSize)
                    {
                        EncryptBlock(output, outputOffset);
                        outputOffset += _blockSize;
                        total += _blockSize;
                    }
                }

                return total;
            }
            
            public int EncryptFinal(byte[] output, int offset, byte[] tag)
            {
                SecurityAssert.AssertBuffer(tag, 0, _tagSize);

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

                var ctr = new CTRBlockCipher(_cipher);
                ctr.Init(new IVParameter(_j0));

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

                    if (_bufferOffset == _blockSize)
                    {
                        DecryptBlock(output, outputOffset);
                        outputOffset += _blockSize;
                        total += _blockSize;
                    }
                }

                return total;
            }
            
            public int DecryptFinal(byte[] input, int inputOffset, byte[] output, int outputOffset)
            {
                SecurityAssert.AssertBuffer(input, inputOffset, _bufferOffset + _tagSize);
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

                var tagCtr = new CTRBlockCipher(_cipher);
                tagCtr.Init(new IVParameter(_j0));

                var digest = _tagHash.Digest();
                var calculatedTag = new byte[16];
                tagCtr.EncryptBlock(digest, 0, calculatedTag, 0);

                var tag = new byte[16];
                Array.Copy(input, inputOffset, tag, 0, _tagSize);

                SecurityAssert.AssertHash(calculatedTag, tag);

                return total;
            }

            private void EncryptBlock(byte[] output, int outputOffset)
            {
                // encrypt block
                var ciphertext = new byte[_blockSize];
                _ctr.EncryptBlock(_buffer, 0, ciphertext, 0);

                // copy to output
                Array.Copy(ciphertext, 0, output, outputOffset, _bufferOffset);

                // update tag hash
                _tagHash.Update(output, outputOffset, _bufferOffset);
                _cSize += _bufferOffset * 8;

                // clear buffer
                _bufferOffset = 0;
                Array.Clear(_buffer, 0, _blockSize);
            }
            
            private void DecryptBlock(byte[] output, int outputOffset)
            {
                // encrypt block
                var plaintext = new byte[_blockSize];
                _ctr.DecryptBlock(_buffer, 0, plaintext, 0);

                // copy to output
                Array.Copy(plaintext, 0, output, outputOffset, _bufferOffset);

                // update tag hash
                _tagHash.Update(_buffer, 0, _bufferOffset);
                _cSize += _bufferOffset * 8;

                // clear buffer
                _bufferOffset = 0;
                Array.Clear(_buffer, 0, _blockSize);
            }
        }
    }
}
