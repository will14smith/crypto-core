﻿using Crypto.TLS.Extensions;
using Crypto.Utils;

namespace Crypto.TLS.Messages.Handshakes
{
    public class HelloExtension
    {
        public HelloExtension(ExtensionType type, byte[] data)
        {
            Type = type;

            SecurityAssert.NotNull(data);
            SecurityAssert.Assert(data.Length >= 0 && data.Length <= 0xFFFF);
            Data = data;
        }

        public ExtensionType Type { get; }
        public byte[] Data { get; }
    }
}
