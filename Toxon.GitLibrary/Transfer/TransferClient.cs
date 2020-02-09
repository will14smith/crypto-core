using System;
using System.Buffers;
using System.Buffers.Text;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using Crypto.Utils;
using Crypto.Utils.IO;
using Toxon.GitLibrary.Packs;

namespace Toxon.GitLibrary.Transfer
{
    public class TransferClient
    {
        private static readonly HttpClient Client = new HttpClient();

        private readonly Uri _baseUri;
        private readonly AuthenticationHeaderValue _authorization;

        public TransferClient(Uri baseUri, string username, string password)
        {
            _baseUri = baseUri.AbsoluteUri.EndsWith("/") ? baseUri : new Uri(baseUri.AbsoluteUri + "/");

            _authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(username + ":" + password)));

        }

        public async Task<DiscoverResponse> DiscoverAsync()
        {
            var discoverUri = new Uri(_baseUri, "info/refs?service=git-receive-pack");

            var httpResponse = await Client.SendAsync(new HttpRequestMessage(HttpMethod.Get, discoverUri)
            {
                Headers = { Authorization = _authorization }
            });
            if (!Equals(httpResponse.Content.Headers.ContentType, MediaTypeHeaderValue.Parse("application/x-git-receive-pack-advertisement")))
            {
                throw new Exception("unexpected content-type");
            }

            var content = await httpResponse.Content.ReadAsByteArrayAsync();
            return DiscoverResponse.Parse(SequenceExtensions.Create<byte>(content));
        }

        public async Task<RequestPackResponse> RequestPackAsync(RequestPackRequest request)
        {
            var uploadUri = new Uri(_baseUri, "git-upload-pack");

            var httpResponse = await Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, uploadUri)
            {
                Content = new ByteArrayContent(request.AsBuffer().ToArray())
                {
                    Headers = { ContentType = MediaTypeHeaderValue.Parse("application/x-git-upload-pack-request") }
                },
                Headers = { Authorization = _authorization }
            });
            if (!Equals(httpResponse.Content.Headers.ContentType, MediaTypeHeaderValue.Parse("application/x-git-upload-pack-result")))
            {
                throw new Exception("unexpected content-type");
            }

            var content = await httpResponse.Content.ReadAsByteArrayAsync();
            return RequestPackResponse.Parse(SequenceExtensions.Create<byte>(content));
        }

        public async Task<SendPackResponse> SendPackAsync(SendPackRequest request)
        {
            var uploadUri = new Uri(_baseUri, "git-receive-pack");

            var httpResponse = await Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, uploadUri)
            {
                Content = new ByteArrayContent(request.AsBuffer().ToArray())
                {
                    Headers = { ContentType = MediaTypeHeaderValue.Parse("application/x-git-receive-pack-request") }
                },
                Headers = { Authorization = _authorization }
            });
            if (!Equals(httpResponse.Content.Headers.ContentType, MediaTypeHeaderValue.Parse("application/x-git-receive-pack-result")))
            {
                throw new Exception("unexpected content-type");
            }

            var content = await httpResponse.Content.ReadAsByteArrayAsync();
            return SendPackResponse.Parse(SequenceExtensions.Create<byte>(content));
        }
    }

    public class SendPackRequest
    {
        public IReadOnlyCollection<string> Capabilities { get; }
        public IReadOnlyCollection<SendPackInstruction> Instructions { get; }
        public PackFile Pack { get; }

        public SendPackRequest(IReadOnlyCollection<string> capabilities, IReadOnlyCollection<SendPackInstruction> instructions, PackFile pack)
        {
            Capabilities = capabilities;
            Instructions = instructions;
            Pack = pack;
        }

        public ReadOnlySequence<byte> AsBuffer()
        {
            var seq = new List<ReadOnlyMemory<byte>>();

            var first = true;
            foreach (var instruction in Instructions)
            {
                if (first)
                {
                    first = false;

                    if (Capabilities.Count > 0)
                    {
                        seq.AddRange(instruction.AsBuffer(Capabilities));
                        continue;
                    }
                }

                seq.AddRange(instruction.AsBuffer(null));
            }

            seq.Add(TransferRecord.Flush);

            using (var stream = new MemoryStream())
            {
                PackFileSerializer.Write(stream, Pack);
                seq.Add(stream.ToArray());
            }

            return seq.ToSequence();
        }
    }

    public class SendPackResponse
    {
        public static SendPackResponse Parse(ReadOnlySequence<byte> content)
        {
            throw new NotImplementedException();
        }
    }
}
