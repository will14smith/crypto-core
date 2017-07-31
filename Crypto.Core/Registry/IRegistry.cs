using System;
using System.Collections.Generic;

namespace Crypto.Core.Registry
{
    public interface IRegistry<TService>
    {
        void Register(Func<TService> factory);
        IReadOnlyCollection<Func<TService>> ResolveAll();
    }

    public interface IRegistry<in TKey, TService>
    {
        void Register(TKey key, Func<TService> factory);
        TService Resolve(TKey key);
        bool IsSupported(TKey key);
    }
}
