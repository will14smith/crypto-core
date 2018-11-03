using System;
using System.Threading.Tasks;
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


            using (var reader = folder.GetFile(".git/objects/pack/pack-d7478dd4a45687cb35fbbb21322346d04fc53dfd.idx").Value.OpenReader())
            {
                var packFile = PackIndexSerializer.Read(reader);
            }
            using (var reader = folder.GetFile(".git/objects/pack/pack-d7478dd4a45687cb35fbbb21322346d04fc53dfd.pack").Value.OpenReader())
            {
                var packFile = PackFileSerializer.Read(reader);
            }

            var repository = GitRepositoryFactory.Open(folder);

            var staging = repository.Staging;

            await staging.BuildIndexAsync();

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
