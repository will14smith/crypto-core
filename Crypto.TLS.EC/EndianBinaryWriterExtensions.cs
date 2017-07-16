﻿using Crypto.EC.Maths;
using Crypto.EC.Maths.Prime;
using Crypto.Utils.IO;

namespace Crypto.TLS.EC
{
    public static class EndianBinaryWriterExtensions
    {
        public static void Write(this EndianBinaryWriter writer, Point<PrimeValue> point)
        {
            // TODO respect ECPointFormatsConfig

            var b = point.ToBytes();
            writer.WriteVariable(1, b);
        }
    }
}