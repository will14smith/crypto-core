using System;
using Toxon.Files;

namespace Toxon.GitLibrary
{
    public static class GitRepositoryFactory
    {
        public static GitRepository Init(IDirectory repositoryFolder)
        {
            throw new NotImplementedException();
        }

        public static GitRepository Open(IDirectory repositoryFolder)
        {
            var gitFolder = repositoryFolder.GetDirectory(".git", true);
            if (gitFolder.HasValue)
            {
                repositoryFolder = gitFolder.Value;
            }

            // TODO verify it is a git repo?

            return new GitRepository(repositoryFolder);
        }

    }
}