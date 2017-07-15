using System;
using System.Collections.Generic;

namespace Crypto.Core.Registry
{
    public interface IRegistry<TService>
    {
        void Register(Func<IServiceProvider, TService> factory);
        IReadOnlyCollection<Func<TService>> ResolveAll(IServiceProvider serviceProvider);
    }

    public interface IRegistry<in TKey, TService>
    {
        void Register(TKey key, Func<IServiceProvider, TService> factory);
        TService Resolve(IServiceProvider serviceProvider, TKey key);
        bool IsSupported(TKey key);
    }
}
