using System;
using System.Collections.Generic;

namespace Crypto.Utils
{
    public struct Option<T>
    {
        public bool HasValue { get; }
        public T Value { get; }

        public Option(T value) { HasValue = true; Value = value; }

        public Option<TOut> Select<TOut>(Func<T, TOut> fn)
        {
            return HasValue ? new Option<TOut>(fn(Value)) : new Option<TOut>();
        }
        public TOut Map<TOut>(Func<T, TOut> some, Func<TOut> none)
        {
            return HasValue ? some(Value) : none();
        }
    }

    public static class Option
    {
        public static Option<T> Some<T>(T value)
        {
            return new Option<T>(value);
        }
        public static Option<T> None<T>()
        {
            return new Option<T>();
        }

        public static T OrElse<T>(this Option<T> opt, Func<T> func)
        {
            return opt.Map(x => x, func);
        }

        public static Option<T> SelectMany<T>(this Option<Option<T>> opt)
        {
            return opt.OrElse(None<T>);
        }
        public static Option<TOut> SelectMany<TIn, TOut>(this Option<TIn> opt, Func<TIn, Option<TOut>> some)
        {
            return opt.Select(some).OrElse(None<TOut>);
        }
    }

    public static class OptionExtensions
    {
        public static Option<TCast> Cast<TValue, TCast>(this Option<TValue> opt)
            where TCast : class
        {
            return opt.Select(x => x as TCast);
        }

        public static Option<TValue> TryGet<TKey, TValue>(this IReadOnlyDictionary<TKey, TValue> dict, TKey key)
        {
            return dict.TryGetValue(key, out var value)
                ? Option.Some(value)
                : Option.None<TValue>();
        }
    }

}
