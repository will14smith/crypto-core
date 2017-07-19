using System;
using System.Numerics;
using Crypto.Core.Randomness;
using Crypto.RSA;
using Crypto.TLS;
using Crypto.TLS.AES;
using Crypto.TLS.DH;
using Crypto.TLS.DH.Config;
using Crypto.TLS.EC;
using Crypto.TLS.GCM;
using Crypto.TLS.IO;
using Crypto.TLS.RC4;
using Crypto.TLS.RSA;
using Crypto.TLS.SHA;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TestProgram
{
    public static class ContainerBuilder
    {
        public static IServiceCollection Create()
        {
            var services = new ServiceCollection();

            // core
            services.AddTLS();
            
            services.AddSingleton<IRandom, DefaultRandomGenerator>();
            services.AddTransient<IStreamAccessor, StreamAccessor>();
            services.AddTransient<INegotiatior, DefaultNegotiatior>();
            
            // features
            services.AddAES();
            services.AddDHKeyExchange(CreateDHParameters());
            services.AddEC();
            services.AddGCM();
            services.AddRC4();
            services.AddRSAKeyReaders();
            services.AddRSAKeyExchange();
            services.AddSHA();
            
            services.AddCipherSuites();

            return services;
        }

        private static DHParameterConfig CreateDHParameters()
        {
            var p = new BigInteger(Convert.FromBase64String("tU9bHsPUA77Tfndcz3qNV91mXBOU34MynSkioJqdOjehwulssAYMJS5vFv4ulCKSnM+jGPiZT9XLKYGasmMjNUQ/uw2QIKfWWjbkJMiFAwkGjwPL+iE/B3IUoYaFcXPKS+C67tkUAnsnzL7BtCoMRiV4kyNgWDsiALOae38gUejDGdnoyxUv8Y2Hoy1jfVNICFtgDd5PavKll+0leob8B3vW/ZpQJHsQSKGW2bUNv4NgUXMkv0QJc6/mQjMnCncGi5yyjX+49+PgUMQ9uZE9mNhqxCkS10c3zIrrauFH6D0qj00YWjIEqFqQRG5/zLoeqKlbvUZO87NUe8D1zI0BmAA="));
            var g = new BigInteger(2);
            
            return new DHParameterConfig(p, g);
        }
    }
}
