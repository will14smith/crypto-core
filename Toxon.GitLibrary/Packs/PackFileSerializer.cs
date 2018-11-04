using System;
using System.Text;

namespace Toxon.GitLibrary.Packs
{
    public partial class PackFileSerializer
    {
        private static readonly ReadOnlyMemory<byte> Signature = Encoding.UTF8.GetBytes("PACK");
    }
}