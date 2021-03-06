﻿using System;
using System.Linq;
using Crypto.Certificates;
using Crypto.TLS.Config;
using Crypto.TLS.Extensions;
using Crypto.TLS.KeyExchanges;
using Crypto.TLS.Messages.Handshakes;
using Crypto.TLS.Records.Strategy;
using Crypto.TLS.Services;
using Crypto.TLS.State;
using Crypto.TLS.Suites.Parameters;
using Crypto.TLS.Suites.Providers;
using Crypto.TLS.Suites.Registries;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TLS
{
    public static class ServiceCollectionExtensions
    {
        public static void AddTLS(this IServiceCollection services)
        {            
            services.AddCipherSuiteServices();
            services.AddStates();
            services.AddRecordStrategies();
            services.AddCoreExtensions();
            
            services.AddScopedConfig();
            services.AddScoped<Connection>();

            services.AddTransient<HandshakeReader>();
            services.AddTransient<HandshakeWriter>();
            
            services.AddTransient<MasterSecretCalculator>();
            services.AddTransient<HandshakeFinishedService>();

            // external services
            services.AddCertificateManager();
        }

        private static void AddCipherSuiteServices(this IServiceCollection services)
        {
            services.AddSingleton<CipherSuitesRegistry>();
            services.AddSingleton<ICipherSuitesProvider,CipherSuitesProvider>();
            services.AddSingleton<CipherAlgorithmRegistry>();
            services.AddSingleton<HashAlgorithmRegistry>();
            services.AddSingleton<SignatureAlgorithmsRegistry>();
            services.AddSingleton<KeyExchangeRegistry>();
            
            services.AddTransient<ICipherSuitesProvider, CipherSuitesProvider>();
            services.AddTransient<IKeyExchangeProvider, KeyExchangeProvider>();
            
            services.AddTransient<ICipherParameterFactoryProvider, CipherParameterFactoryProvider>();
            services.AddTransient<ISignatureCipherParameterFactoryProvider, SignatureCipherParameterFactoryProvider>();
        }

        private static void AddStates(this IServiceCollection services)
        {
            var assemblies = AppDomain.CurrentDomain.GetAssemblies();
            var types = assemblies.SelectMany(x => x.GetTypes());

            var stateTypes = types.Where(x => typeof(IState).IsAssignableFrom(x) && x.IsClass && !x.IsAbstract);

            foreach (var type in stateTypes)
            {
                services.AddTransient(type);
            }
        }

        private static void AddRecordStrategies(this IServiceCollection services)
        {
            services.AddTransient<PlaintextStrategy>();
            services.AddTransient<CipherStrategy>();
            services.AddTransient<BlockCipherStrategy>();
            services.AddTransient<AEADCipherStrategy>();
        }
        
        private static void AddScopedConfig(this IServiceCollection services)
        {
            services.AddScoped<AEADCipherConfig>();
            services.AddScoped<BlockCipherConfig>();
            services.AddScoped<CertificateConfig>();
            services.AddScoped<CipherSuiteConfig>();
            services.AddScoped<EndConfig>();
            services.AddScoped<HandshakeConfig>();
            services.AddScoped<KeyConfig>();
            services.AddScoped<RandomConfig>();
            services.AddScoped<SequenceConfig>();
            services.AddScoped<SessionConfig>();
            services.AddScoped<VersionConfig>();
        }
    }
}

