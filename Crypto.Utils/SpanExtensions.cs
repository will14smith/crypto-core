using System;

namespace Crypto.Utils
{
    public static class SpanExtensions
    {
        public static Span<T> ToSpan<T>(this T[] array)
        {
            return new Span<T>(array);
        }

        public static bool EqualConstantTime(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
        {
            if (a.Length != b.Length)
            {
                return false;
            }

            var result = 0;
            for (var i = 0; i < a.Length; i++)
            {
                result |= a[i] ^ b[i];
            }
            return result == 0;
        }

        public static TwoSplitResult<T> Split<T>(this Span<T> span, int offset)
        {
            var pre = span.Slice(0, offset);
            var post = span.Slice(offset);

            return new TwoSplitResult<T>(pre, post);
        }
        public static ThreeSplitResult<T> Split<T>(this Span<T> span, int offset, int length)
        {
            var pre = span.Slice(0, offset);
            var content = span.Slice(offset, length);
            var post = span.Slice(offset + length);

            return new ThreeSplitResult<T>(pre, content, post);
        }

        public static ReadOnlyTwoSplitResult<T> Split<T>(this ReadOnlySpan<T> span, int offset)
        {
            var pre = span.Slice(0, offset);
            var post = span.Slice(offset);

            return new ReadOnlyTwoSplitResult<T>(pre, post);
        }
        public static ReadOnlyThreeSplitResult<T> Split<T>(this ReadOnlySpan<T> span, int offset, int length)
        {
            var pre = span.Slice(0, offset);
            var content = span.Slice(offset, length);
            var post = span.Slice(offset + length);

            return new ReadOnlyThreeSplitResult<T>(pre, content, post);
        }
    }

    public ref struct ThreeSplitResult<T>
    {
        public readonly Span<T> Pre;
        public readonly Span<T> Content;
        public readonly Span<T> Post;

        public ThreeSplitResult(in Span<T> pre, in Span<T> content, in Span<T> post)
        {
            Pre = pre;
            Content = content;
            Post = post;
        }

        public void Deconstruct(out Span<T> pre, out Span<T> content, out Span<T> post)
        {
            pre = Pre;
            content = Content;
            post = Post;
        }
    }

    public ref struct TwoSplitResult<T>
    {
        public readonly Span<T> Pre;
        public readonly Span<T> Post;

        public TwoSplitResult(in Span<T> pre, in Span<T> post)
        {
            Pre = pre;
            Post = post;
        }

        public void Deconstruct(out Span<T> pre, out Span<T> post)
        {
            pre = Pre;
            post = Post;
        }
    }

    public ref struct ReadOnlyThreeSplitResult<T>
    {
        public readonly ReadOnlySpan<T> Pre;
        public readonly ReadOnlySpan<T> Content;
        public readonly ReadOnlySpan<T> Post;

        public ReadOnlyThreeSplitResult(in ReadOnlySpan<T> pre, in ReadOnlySpan<T> content, in ReadOnlySpan<T> post)
        {
            Pre = pre;
            Content = content;
            Post = post;
        }

        public void Deconstruct(out ReadOnlySpan<T> pre, out ReadOnlySpan<T> content, out ReadOnlySpan<T> post)
        {
            pre = Pre;
            content = Content;
            post = Post;
        }
    }

    public ref struct ReadOnlyTwoSplitResult<T>
    {
        public readonly ReadOnlySpan<T> Pre;
        public readonly ReadOnlySpan<T> Post;

        public ReadOnlyTwoSplitResult(in ReadOnlySpan<T> pre, in ReadOnlySpan<T> post)
        {
            Pre = pre;
            Post = post;
        }

        public void Deconstruct(out ReadOnlySpan<T> pre, out ReadOnlySpan<T> post)
        {
            pre = Pre;
            post = Post;
        }
    }
}
