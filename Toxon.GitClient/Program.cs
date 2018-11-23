using System;
using System.Threading.Tasks;
using Crypto.Utils.IO;
using Toxon.Files;
using Toxon.Files.Physical;
using Toxon.GitLibrary;
using Toxon.GitLibrary.Objects;
using Toxon.GitLibrary.Packs;

namespace Toxon.GitClient
{
    class Program
    {
        static async Task Main(string[] args)
        {
            var folder = PhysicalDirectory.Open(@"C:\projects\test");

            using (var input = folder.GetFile("pack-1d942b6e7bbc2f7987b40610a46e1d31ea50ffd6.pack").Value.OpenReader())
            using (var output = folder.CreateOrReplaceFile("pack-1d942b6e7bbc2f7987b40610a46e1d31ea50ffd6.idx2").Value.OpenWriter())
            {
                input.Position = 8;

                var reader = new EndianBinaryReader(EndianBitConverter.Big, input);
                var index = PackIndexBuilder.Build(reader);
                index.Write(output);
            }

            var repository = GitRepositoryFactory.Open(folder);

            var staging = repository.Staging;

            //await staging.BuildIndexAsync();

            //var actor = new CommitObject.Actor("Will Smith", "will@toxon.co.uk", DateTimeOffset.Now);
            //await staging.StageAsync(folder.GetFile("c.txt").Value);
            //await staging.CommitAsync(actor, actor, "Commit c.txt!");

            var files = await staging.ListAsync();
            foreach (var file in files)
            {
                Console.WriteLine(file);
            }

            Console.ReadLine();
        }
    }
}
