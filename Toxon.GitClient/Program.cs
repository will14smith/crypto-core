using System;
using System.Buffers;
using System.IO;
using System.Threading.Tasks;
using Crypto.Utils;
using Toxon.Files.Physical;
using Toxon.GitLibrary.Objects;
using Toxon.GitLibrary.Packs;
using Toxon.GitLibrary.Transfer;

namespace Toxon.GitClient
{
    class Program
    {
        static async Task Main(string[] args)
        {
            var folder = PhysicalDirectory.Open(@"C:\projects\test");

            var client = new TransferClient(new Uri("http://localhost:9090/root/test.git"), "root", "password");
            var discover = await client.DiscoverAsync();

            var reqRequest = new RequestPackRequest(new string[0], new ObjectRef[] { discover.Branches["refs/heads/master"] }, new ObjectRef[0]);
            var reqResponse = await client.RequestPackAsync(reqRequest);

            PackFile pack;
            using (var packStream = new MemoryStream(reqResponse.PackFile.ToArray()))
            {
                pack = PackFileSerializer.Read(packStream);
            }

            var sendRequest = new SendPackRequest(discover.Capabilities, new SendPackInstruction[]
            {
                new SendPackInstruction.Create("refs/heads/new-branch", ObjectRefFromString("8501c06e8183ec417565d757c9d6d3f6144ada39")),
                new SendPackInstruction.Update("refs/heads/master", discover.Branches["refs/heads/master"], ObjectRefFromString("96cbcdfd7b87da4498050b81a263f6d7da42302f")), 
                new SendPackInstruction.Delete("refs/heads/test", discover.Branches["refs/heads/test"]), 

            }, pack);
            var sendResponse = await client.SendPackAsync(sendRequest);
            
            Console.WriteLine(sendResponse);

            //using (var input = folder.GetFile("pack-1d942b6e7bbc2f7987b40610a46e1d31ea50ffd6.pack").Value.OpenReader())
            //using (var output = folder.CreateOrReplaceFile("pack-1d942b6e7bbc2f7987b40610a46e1d31ea50ffd6.idx2").Value.OpenWriter())
            //{
            //    input.Position = 8;

            //    var reader = new EndianBinaryReader(EndianBitConverter.Big, input);
            //    var index = PackIndexBuilder.Build(reader);
            //    index.Write(output);
            //}

            //var repository = GitRepositoryFactory.Open(folder);

            //var staging = repository.Staging;

            //await staging.BuildIndexAsync();

            //var actor = new CommitObject.Actor("Will Smith", "will@toxon.co.uk", DateTimeOffset.Now);
            //await staging.StageAsync(folder.GetFile("c.txt").Value);
            //await staging.CommitAsync(actor, actor, "Commit c.txt!");

            //var files = await staging.ListAsync();
            //foreach (var file in files)
            //{
            //    Console.WriteLine(file);
            //}

            Console.ReadLine();
        }

        private static ObjectRef ObjectRefFromString(string hash)
        {
            return new ObjectRef(HexConverter.FromHex(hash).ToArray());
        }
    }
}
