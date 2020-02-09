using System;
using System.Collections.Generic;
using Crypto.Core.Hashing;
using Crypto.TLS.Messages.Handshakes;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.TLS.Config
{
    public class HandshakeConfig
    {
        private readonly List<byte[]> _messages = new List<byte[]>();
                
        public void UpdateVerification(HandshakeType type, uint length, byte[] body)
        {
            UpdateVerification(new[] { (byte)type }, 0, 1);
            UpdateVerification(EndianBitConverter.Big.GetBytes(length), 1, 3);
            UpdateVerification(body, 0, body.Length);
        }
        
        public void UpdateVerification(byte[] buffer, int offset, int length)
        {
            SecurityAssert.AssertBuffer(buffer, offset, length);
            var output = new byte[length];
            
            Array.Copy(buffer, offset, output, 0, length);

            _messages.Add(output);
        }

        public byte[] ComputeVerification(IDigest digest)
        {
            foreach (var message in _messages)
            {
                digest.Update(message, 0, message.Length);
            }

            return digest.DigestBuffer();
        }
    }
}
