using System;

namespace Crypto.TLS.Config
{
    public class SequenceConfig
    {
        public long Read { get; private set;  }
        public long Write { get; private set; }

        public long GetReadThenIncrement()
        {
            return Read++;
        }
        public long GetWriteThenIncrement()
        {
            return Write++;
        }

        public long GetThenIncrement(ConnectionDirection direction)
        {
            switch (direction)
            {
                case ConnectionDirection.Read:
                    return GetReadThenIncrement();
                case ConnectionDirection.Write:
                    return GetWriteThenIncrement();
                default:
                    throw new ArgumentOutOfRangeException(nameof(direction), direction, null);
            }
        }
    }
}
