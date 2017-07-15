using System;

namespace Crypto.TLS.Messages.Alerts
{
    [Flags]
    public enum AlertLevel : byte
    {
        Warning = 1,
        Fatal = 2,
    }
}