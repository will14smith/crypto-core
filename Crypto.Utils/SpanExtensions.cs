using System;

namespace Crypto.Utils
{
    public static  class SpanExtensions
    {
        public static TwoSplitResult<T> Split<T>(this Span<T> span, int offset)
        {
            var pre = span.Slice(0, offset);
            var post = span.Slice(offset);

            return new TwoSplitResult<T>(pre, post);
        } 
        public static ReadOnlyTwoSplitResult<T> Split<T>(this ReadOnlySpan<T> span, int offset)
        {
            var pre = span.Slice(0, offset);
            var post = span.Slice(offset);

            return new ReadOnlyTwoSplitResult<T>(pre, post);
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