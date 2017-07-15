using System;
using System.Linq;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.Core.Registry
{
    public static class RegistryExtensions
    {
        public static IServiceCollection Update<TRegistry>(this IServiceCollection collection, Func<TRegistry, TRegistry> updateFunc)
        {
            var serviceType = typeof(TRegistry);

            var registeredServiceDescriptor = collection.FirstOrDefault(s => s.ServiceType == serviceType);
            if (registeredServiceDescriptor != null)
            {
                collection.Remove(registeredServiceDescriptor);
            }
            
            collection.Add(new ServiceDescriptor(serviceType, updateFunc((TRegistry)registeredServiceDescriptor?.ImplementationInstance)));
            
            return collection;
        }
    }
}