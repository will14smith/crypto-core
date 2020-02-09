using System;

namespace Crypto.Core.Randomness
{
    public class DefaultRandomGenerator : IRandom
    {
        private static readonly Random Global = new Random();
        [ThreadStatic] private static Random? _local;

        public DefaultRandomGenerator()
        {
            if (_local != null)
            {
                return;
            }

            int seed;
            lock (Global)
            {
                seed = Global.Next();
            }
            _local = new Random(seed);
        }

        public int RandomInt(int min, int max)
        {
            return _local!.Next(min, max);
        }

        public byte[] RandomBytes(int length)
        {
            var buffer = new byte[length];
            
            _local!.NextBytes(buffer);

            return buffer;
        }
    }
}
