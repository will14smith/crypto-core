using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using Crypto.Utils;
using ICSharpCode.SharpZipLib.Zip.Compression;

namespace Toxon.GitLibrary
{
    public static class Zlib
    {
        public static ReadOnlySequence<byte> Inflate(in Stream input)
        {
            const int readBufferSize = 1024;
            const int inflateBufferSize = 1024;

            var inflater = new Inflater(false);

            var memories = new List<ReadOnlyMemory<byte>>();

            while (!inflater.IsFinished)
            {
                var buffer = new byte[readBufferSize];
                var actualBufferLength = input.Read(buffer, 0, readBufferSize);

                inflater.SetInput(buffer, 0, actualBufferLength);

                while (!inflater.IsNeedingInput)
                {
                    var output = new byte[inflateBufferSize];
                    var inflateLength = inflater.Inflate(output, 0, inflateBufferSize);
                    if (inflateLength == 0) break;

                    memories.Add(new ReadOnlyMemory<byte>(output, 0, inflateLength));
                }

                if (inflater.IsNeedingDictionary) throw new Exception("missing dictionary");
            }

            input.Seek(-inflater.RemainingInput, SeekOrigin.Current);

            return memories.ToSequence();
        }
        public static ReadOnlySequence<byte> Inflate(in ReadOnlySequence<byte> input)
        {
            const int inflateBufferSize = 1024;

            var inflater = new Inflater(false);

            var memories = new List<ReadOnlyMemory<byte>>();
            var inputIterator = input.GetEnumerator();

            while (!inflater.IsFinished)
            {
                if (!inputIterator.MoveNext()) throw new Exception("input ended before inflation");

                // TODO :( ToArray
                var buffer = inputIterator.Current.ToArray();
                inflater.SetInput(buffer, 0, buffer.Length);

                while (!inflater.IsNeedingInput)
                {
                    var output = new byte[inflateBufferSize];
                    var inflateLength = inflater.Inflate(output, 0, inflateBufferSize);
                    if (inflateLength == 0) break;

                    memories.Add(new ReadOnlyMemory<byte>(output, 0, inflateLength));
                }

                if (inflater.IsNeedingDictionary) throw new Exception("missing dictionary");
            }

            return memories.ToSequence();
        }

        public static void Deflate(in Stream output, in ReadOnlySequence<byte> input)
        {
            const int deflateBufferSize = 1024;

            var deflater = new Deflater(Deflater.BEST_COMPRESSION, false);

            foreach (var segment in input)
            {
                // TODO :( ToArray
                deflater.SetInput(segment.ToArray());

                while (!deflater.IsNeedingInput)
                {
                    // TODO :( Allocate buffer
                    var buffer = new byte[deflateBufferSize];
                    var deflateLength = deflater.Deflate(buffer, 0, deflateBufferSize);
                    if (deflateLength == 0) break;

                    output.Write(buffer, 0, deflateLength);
                }
            }

            deflater.Finish();
            while (!deflater.IsFinished)
            {
                // TODO :( Allocate buffer
                var buffer = new byte[deflateBufferSize];
                var deflateLength = deflater.Deflate(buffer, 0, deflateBufferSize);
                if (deflateLength == 0) break;

                output.Write(buffer, 0, deflateLength);
            }

            output.Flush();
        }
    }
}
