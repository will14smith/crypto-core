using System;
using System.Buffers;
using System.Collections.Generic;
using Crypto.Core.Hashing;
using Crypto.TLS.Messages.Handshakes;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.TLS.Config
{
    public class HandshakeConfig
    {
        private readonly List<ReadOnlyMemory<byte>> _messages = new List<ReadOnlyMemory<byte>>();
                
        public void UpdateVerification(HandshakeType type, uint length, byte[] body)
        {
            UpdateVerification(new[] { (byte)type });
            UpdateVerification(EndianBitConverter.Big.GetBytes(length).AsSpan(1, 3));
            UpdateVerification(body);
        }
        
        public void UpdateVerification(ReadOnlySpan<byte> buffer)
        {           
            _messages.Add(buffer.ToArray());
        }

        public ReadOnlySpan<byte> ComputeVerification(IDigest digest)
        {
            foreach (var message in _messages)
            {
                digest.Update(message.Span);
            }

            return digest.Digest();
        }
    }
}
