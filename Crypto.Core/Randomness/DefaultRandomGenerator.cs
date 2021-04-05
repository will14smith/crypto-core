using System;

namespace Crypto.Core.Randomness
{
    public class DefaultRandomGenerator : IRandom
    {
        private static readonly Random Global = new Random();
        [ThreadStatic] private static Random? _local;

        private static Random Local
        {
            get
            {
                if (_local != null)
                {
                    return _local;
                }

                int seed;
                lock (Global)
                {
                    seed = Global.Next();
                }
                _local = new Random(seed);
                return _local;
            }
        }
        
        public int RandomInt(int min, int max)
        {
            return Local.Next(min, max);
        }

        public byte[] RandomBytes(int length)
        {
            var buffer = new byte[length];
            
            Local.NextBytes(buffer);

            return buffer;
        }
    }
}
