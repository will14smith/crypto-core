using System.Collections.Generic;

namespace Crypto.TLS.EC.Config
{
    public class ECPointFormatsConfig
    {
        public IReadOnlyCollection<ECPointFormat>? SupportedPointFormats { get; set; }
    }
}
