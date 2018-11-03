using System;
using System.Buffers;

namespace Toxon.GitLibrary.Index
{
    public class IndexEntry
    {
        public string Name { get; }
        public ReadOnlySequence<byte> Hash { get; }
        public uint Size { get; }

        public uint Flags { get; }
        public uint Mode { get; }

        public DateTime Created { get; }
        public DateTime Modified { get; }

        public uint DeviceId { get; }
        public uint Inode { get; }


        public uint Uid { get; }
        public uint Gid { get; }

        public IndexEntry(string name, ReadOnlySequence<byte> hash, uint size, uint flags, uint mode, DateTime created, DateTime modified, uint deviceId, uint inode, uint uid, uint gid)
        {
            Name = name;
            Hash = hash;
            Size = size;

            Created = created;
            Modified = modified;

            Flags = flags;
            Mode = mode;

            DeviceId = deviceId;
            Inode = inode;

            Uid = uid;
            Gid = gid;
        }

        public override string ToString()
        {
            return Name;
        }
    }
}