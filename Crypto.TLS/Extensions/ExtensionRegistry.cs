using System;
using System.Collections.Generic;
using System.Linq;
using Crypto.Core.Registry;
using Crypto.Utils;

namespace Crypto.TLS.Extensions
{
    public class ExtensionRegistry : BaseRegistry<ExtensionType, IExtension>
    {
        public Option<IExtension> TryResolve(IServiceProvider serviceProvider, ExtensionType key)
        {
            if (Factories.TryGetValue(key, out var factory))
            {
                return Option.Some(factory(serviceProvider));
            }

            return Option.None<IExtension>();
        }

        public IReadOnlyCollection<IExtension> ResolveAll(IServiceProvider serviceProvider)
        {
            return Keys.Select(key => Resolve(serviceProvider, key)).ToList();
        }
    }
}
