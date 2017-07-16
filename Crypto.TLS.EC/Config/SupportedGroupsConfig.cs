using System.Collections.Generic;
using Crypto.TLS.EC.Services;

namespace Crypto.TLS.EC.Config
{
    public class SupportedGroupsConfig
    {
        public IReadOnlyCollection<NamedCurve> SupportedGroups { get; set; }
    }
}
