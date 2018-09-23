using System;
using System.Collections.Generic;
using Crypto.Core.Registry;
using Crypto.Utils;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TLS.Extensions
{
    public static class ServiceExtensions
    {
        internal static IServiceCollection AddCoreExtensions(this IServiceCollection serviceCollection)
        {
            serviceCollection
                .RegisterExtension<SignatureAlgorithmsExtension>(ExtensionType.SignatureAlgorithms)
                .AddScoped<SignatureAlgorithmsExtension.Config>();

            return serviceCollection;
        }
        
        public static IServiceCollection RegisterExtension<T>(this IServiceCollection serviceCollection, ExtensionType extensionType)
            where T : class, IExtension
        {
            serviceCollection.AddTransient<T>();

            return serviceCollection.Update<ExtensionRegistry>(prev =>
            {
                prev = prev ?? new ExtensionRegistry();

                prev.Register(extensionType, sp => sp.GetRequiredService<T>());

                return prev;
            });
        }

        public static Option<IExtension> TryResolveExtension(this IServiceProvider serviceProvider, ExtensionType extensionType)
        {
            return serviceProvider.GetRequiredService<ExtensionRegistry>().TryResolve(serviceProvider, extensionType);
        }
        public static IReadOnlyCollection<IExtension> ResolveAllExtensions(this IServiceProvider serviceProvider)
        {
            return serviceProvider.GetRequiredService<ExtensionRegistry>().ResolveAll(serviceProvider);
        }

        public static IServiceCollection AddRenegotiationInfo(this IServiceCollection serviceCollection)
        {
            serviceCollection
                .RegisterExtension<RenegotiationInfoExtension>(RenegotiationInfoExtension.Type)
                .AddScoped<RenegotiationInfoExtension.Config>();

            return serviceCollection;
        }
    }
}
