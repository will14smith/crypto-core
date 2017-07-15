using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using Crypto.TLS.State;
using Crypto.Certificates;
using Crypto.Utils;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TestProgram
{
    class Program
    {
        static void Main(string[] args)
        {
            var services = ContainerBuilder.Create();
            var serviceProvider = services.BuildServiceProvider();

            LoadCertificates(serviceProvider.GetRequiredService<CertificateManager>());

            var server = new TcpListener(IPAddress.Any, 443);
            server.Start();
            
            while (true)
            {
                var client = server.AcceptTcpClient();

                Console.WriteLine("Client connected: " + client.Client.RemoteEndPoint);

                using (var scope = serviceProvider.CreateScope())
                {
                    var scopedServiceProvider = scope.ServiceProvider;

                    scopedServiceProvider.GetRequiredService<IStreamAccessor>().Stream = client.GetStream();

                    IState state = scopedServiceProvider.GetRequiredService<InitialState>();
                    while (true)
                    {
                        Console.WriteLine("In state " + state.State);
                        state = state.Run();
                        if (state == null)
                        {
                            client.Close();
                            break;
                        }
                    }
                }
            }
        }

        private static void LoadCertificates(CertificateManager certificates)
        {
            var rsaCert = PEMReader.TryConvertFromBase64(File.ReadAllBytes("localhost_rsa.cert"));
            SecurityAssert.Assert(rsaCert.Count == 1);
            certificates.AddCertificate(rsaCert[0].RawData);

            var rsaKey = PEMReader.TryConvertFromBase64(File.ReadAllBytes("localhost_rsa.key"));
            SecurityAssert.Assert(rsaKey.Count == 1);
            certificates.AddPrivateKey(rsaKey[0].RawData);
            
            var dhCert = PEMReader.TryConvertFromBase64(File.ReadAllBytes("localhost_dh.cert"));
            SecurityAssert.Assert(dhCert.Count == 1);
            certificates.AddCertificate(dhCert[0].RawData);

            var dhKey = PEMReader.TryConvertFromBase64(File.ReadAllBytes("localhost_dh.key"));
            SecurityAssert.Assert(dhKey.Count == 1);
            certificates.AddPrivateKey(dhKey[0].RawData);
        }
    }
}
