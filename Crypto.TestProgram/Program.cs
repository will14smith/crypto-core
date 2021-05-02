using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using Crypto.Certificates;
using Crypto.TLS.IO;
using Crypto.Utils;
using Microsoft.Extensions.DependencyInjection;

namespace Crypto.TestProgram
{
    class Program
    {
        static void Main(string[] args)
        {
            ServerMain(args);
        }

        static void ClientMain(string[] args)
        {
            var services = ContainerBuilder.Create();
            var serviceProvider = services.BuildServiceProvider();

            var client = new TcpClient();
            client.Connect(new IPEndPoint(IPAddress.Loopback, 4433));
            
            var stream = new TLSStream(client.GetStream(), serviceProvider);

            stream.AuthenticateAsClient();

            var reader = new StreamReader(stream);
            var writer = new StreamWriter(stream) { AutoFlush = true };

            var msg = reader.ReadLine();
            writer.WriteLine("Thanks! Your message was: " + msg);
        }

        static void ServerMain(string[] args)
        {
            var services = ContainerBuilder.Create();
            var serviceProvider = services.BuildServiceProvider();

            LoadCertificates(serviceProvider.GetRequiredService<CertificateManager>());

            var server = new TcpListener(IPAddress.Any, 4433);
            server.Start();

            while (true)
            {
                var client = server.AcceptTcpClient();

                new Thread(HandleClient).Start(((TcpClient, IServiceProvider)) (client, serviceProvider));
            }
        }

        private static void HandleClient(object? obj)
        {
            var (client, serviceProvider) = ((TcpClient, IServiceProvider)) obj;
            
            Console.WriteLine("Client connected: " + client.Client.RemoteEndPoint);

            try
            {
                var stream = new TLSStream(client.GetStream(), serviceProvider);

                try
                {
                    stream.AuthenticateAsServer();
                }
                catch (UnableToEstablishSecureConnectionException ex)
                {
                    Console.WriteLine(ex);
                    return;
                }

                var reader = new StreamReader(stream);
                var writer = new StreamWriter(stream) {AutoFlush = true};

                var msg = reader.ReadLine();
                writer.WriteLine("Thanks! Your message was: " + msg);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex);
                client.Close();
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

            var ecCert = PEMReader.TryConvertFromBase64(File.ReadAllBytes("localhost_ec.cert"));
            SecurityAssert.Assert(ecCert.Count == 1);
            certificates.AddCertificate(ecCert[0].RawData);

            var ecKey = PEMReader.TryConvertFromBase64(File.ReadAllBytes("localhost_ec.key"));
            SecurityAssert.Assert(ecKey.Count == 1);
            certificates.AddPrivateKey(ecKey[0].RawData);

            var dhCert = PEMReader.TryConvertFromBase64(File.ReadAllBytes("localhost_dh.cert"));
            SecurityAssert.Assert(dhCert.Count == 1);
            certificates.AddCertificate(dhCert[0].RawData);

            var dhKey = PEMReader.TryConvertFromBase64(File.ReadAllBytes("localhost_dh.key"));
            SecurityAssert.Assert(dhKey.Count == 1);
            certificates.AddPrivateKey(dhKey[0].RawData);
        }
    }
}
