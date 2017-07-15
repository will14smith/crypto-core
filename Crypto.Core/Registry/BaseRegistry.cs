using System;
using System.Collections.Generic;

namespace Crypto.Core.Registry
{
    public abstract class BaseRegistry<TKey, TService> : IRegistry<TKey, TService>
    {
        protected readonly ISet<TKey> Keys
            = new HashSet<TKey>();

        protected readonly Dictionary<TKey, Func<IServiceProvider, TService>> Factories
            = new Dictionary<TKey, Func<IServiceProvider, TService>>();

        public void Register(TKey key, Func<IServiceProvider, TService> factory)
        {
            Keys.Add(key);
            Factories.Add(key, factory);
        }

        public TService Resolve(IServiceProvider serviceProvider, TKey key)
        {
            return Factories[key](serviceProvider);
        }

        public bool IsSupported(TKey key)
        {
            return Keys.Contains(key);
        }
    }
}