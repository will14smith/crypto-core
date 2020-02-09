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

        public AEADResult Encrypt(ReadOnlySpan<byte> input, Span<byte> output)
        {
            if(_state == null) throw new InvalidOperationException("GCM is not initialized");
            return _state.Encrypt(input, output);
        }

        public AEADResult EncryptFinal(AEADResult previousResult)
        {
            if(_state == null) throw new InvalidOperationException("GCM is not initialized");
            return _state.EncryptFinal(previousResult);
        }

        public AEADResult Decrypt(ReadOnlySpan<byte> input, Span<byte> output)
        {
            if(_state == null) throw new InvalidOperationException("GCM is not initialized");
            return _state.Decrypt(input, output);
        }

        public AEADResult DecryptFinal(AEADResult previousResult)
        {
            if(_state == null) throw new InvalidOperationException("GCM is not initialized");
            return _state.DecryptFinal(previousResult);
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
            
            public AEADResult Encrypt(ReadOnlySpan<byte> input, Span<byte> output)
            {
                foreach (var t in input)
                {
                    _buffer[_bufferOffset++] = t;

                    if (_bufferOffset == _blockSize)
                    {
                        output = EncryptBlock(output);
                    }
                }

                return new AEADResult(new ReadOnlySpan<byte>(), output);
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

                var ctr = new CTRBlockCipher(_cipher);
                ctr.Init(new IVParameter(new NullCipherParameter(), _j0));

                ctr.EncryptBlock(_tagHash.Digest(), output);

                return new AEADResult(previousResult.RemainingInput, output);
            }
            
            public AEADResult Decrypt(ReadOnlySpan<byte> input, Span<byte> output)
            {
                // Don't consume what could be the tag
                var length = input.Length - _tagSize;

                // TODO round length up to BlockLength
                SecurityAssert.AssertInputOutputBuffers(input, output, length);

                for (var index = 0; index < length; index++)
                {
                    var t = input[index];
                    _buffer[_bufferOffset++] = t;

                    if (_bufferOffset == _blockSize)
                    {
                        output = DecryptBlock(output);
                    }
                }

                return new AEADResult(input.Slice(length), output);
            }
            
            public AEADResult DecryptFinal(AEADResult previousResult)
            {
                // TODO SecurityAssert.AssertBuffer(input, inputOffset, _bufferOffset + TagLength);
                // TODO SecurityAssert.AssertBuffer(output, outputOffset, _bufferOffset);

                // Consume everything but the Tag
                previousResult = Decrypt(previousResult.RemainingInput, previousResult.RemainingOutput);
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

                var tagCtr = new CTRBlockCipher(_cipher);
                tagCtr.Init(new IVParameter(new NullCipherParameter(), _j0));

                var digest = _tagHash.Digest();
                var calculatedTag = new byte[16];
                tagCtr.EncryptBlock(digest, calculatedTag);

                var tag = input.Slice(0, _tagSize).ToArray();
                SecurityAssert.AssertHash(calculatedTag, tag);

                return new AEADResult(input.Slice(_tagSize), output);
            }

            private Span<byte> EncryptBlock(Span<byte> output)
            {
                var bufferLength = _bufferOffset;

                // encrypt block
                var ciphertext = new byte[_blockSize];
                _ctr.EncryptBlock(_buffer, ciphertext);

                // copy to output
                ciphertext.AsSpan().Slice(0, bufferLength).CopyTo(output);

                // update tag hash
                _tagHash.Update(output.Slice(0, bufferLength));
                _cSize += bufferLength * 8;

                // clear buffer
                _bufferOffset = 0;
                Array.Clear(_buffer, 0, _blockSize);

                return output.Slice(bufferLength);
            }
            
            private Span<byte> DecryptBlock(Span<byte> output)
            {
                var bufferLength = _bufferOffset;

                // encrypt block
                var plaintext = new byte[_blockSize];
                _ctr.DecryptBlock(_buffer, plaintext);

                // copy to output
                plaintext.AsSpan().Slice(0, bufferLength).CopyTo(output);
                
                // update tag hash
                _tagHash.Update(_buffer.AsSpan().Slice(0, bufferLength));
                _cSize += bufferLength * 8;

                // clear buffer
                _bufferOffset = 0;
                Array.Clear(_buffer, 0, _blockSize);

                return output.Slice(bufferLength);
            }
        }
    }
}
