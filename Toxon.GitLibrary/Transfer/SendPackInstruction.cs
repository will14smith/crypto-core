using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Crypto.Utils;
using Toxon.GitLibrary.Objects;

namespace Toxon.GitLibrary.Transfer
{
    public abstract class SendPackInstruction
    {
        private static readonly ReadOnlyMemory<byte> Space = Encoding.UTF8.GetBytes(" ");
        private static readonly ReadOnlyMemory<byte> Null = new byte[1];
        private static readonly ReadOnlyMemory<byte> NewLine = Encoding.UTF8.GetBytes("\n");

        public string Name { get; }

        protected SendPackInstruction(string name)
        {
            Name = name;
        }

        public abstract IEnumerable<ReadOnlyMemory<byte>> AsBuffer(IReadOnlyCollection<string> capabilities);

        protected IEnumerable<ReadOnlyMemory<byte>> AsBuffer(IReadOnlyCollection<string> capabilities, ObjectRef oldRef, ObjectRef newRef)
        {
            var nameBuffer = Encoding.UTF8.GetBytes(Name);
            var length = 4 + 40 + 1 + 40 + 1 + nameBuffer.Length + ((1 + capabilities?.Sum(x => x.Length + 1)) ?? 0) + 1;

            yield return LengthBuffer(length);
            yield return Encoding.UTF8.GetBytes(HexConverter.ToHex(oldRef.Hash));
            yield return Space;
            yield return Encoding.UTF8.GetBytes(HexConverter.ToHex(newRef.Hash));
            yield return Space;
            yield return nameBuffer;

            if (capabilities != null)
            {
                yield return Null;

                foreach (var capability in capabilities)
                {
                    yield return Space;
                    yield return Encoding.UTF8.GetBytes(capability);
                }
            }

            yield return NewLine;
        }

        private static byte[] LengthBuffer(int length)
        {
            var lengthBuffer = new[] { (byte)'0', (byte)'0', (byte)'0', (byte)'0' };
            var lengthBufferOffset = 3;
            while (length > 0)
            {
                lengthBuffer[lengthBufferOffset--] = (byte)HexConverter.ToHexNibble((byte)(length & 0xf));

                length >>= 4;
            }

            return lengthBuffer;
        }

        public class Create : SendPackInstruction
        {
            public ObjectRef ObjectId { get; }

            public Create(string name, ObjectRef objectId) : base(name)
            {
                ObjectId = objectId;
            }

            public override IEnumerable<ReadOnlyMemory<byte>> AsBuffer(IReadOnlyCollection<string> capabilities) => AsBuffer(capabilities, ObjectRef.Zero, ObjectId);
        }
        public class Update : SendPackInstruction
        {

            public ObjectRef OldObjectId { get; }
            public ObjectRef NewObjectId { get; }

            public Update(string name, ObjectRef oldObjectId, ObjectRef newObjectId) : base(name)
            {
                OldObjectId = oldObjectId;
                NewObjectId = newObjectId;
            }

            public override IEnumerable<ReadOnlyMemory<byte>> AsBuffer(IReadOnlyCollection<string> capabilities) => AsBuffer(capabilities, OldObjectId, NewObjectId);
        }
        public class Delete : SendPackInstruction
        {
            public ObjectRef ObjectId { get; }

            public Delete(string name, ObjectRef objectId) : base(name)
            {
                ObjectId = objectId;
            }

            public override IEnumerable<ReadOnlyMemory<byte>> AsBuffer(IReadOnlyCollection<string> capabilities) => AsBuffer(capabilities, ObjectId, ObjectRef.Zero);
        }
    }
}