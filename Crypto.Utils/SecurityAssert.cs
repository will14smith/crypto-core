﻿using System;
using System.Runtime.CompilerServices;
using System.Security;
using JetBrains.Annotations;

namespace Crypto.Utils
{
    public static class SecurityAssert
    {
        [AssertionMethod]
        public static void NotNull<T>([AssertionCondition(AssertionConditionType.IS_NOT_NULL)] T obj, [CallerMemberName] string? callerName = null, [CallerLineNumber] int callerLine = 0, [CallerFilePath] string? callerFile = null)
            where T : class?
        {
            InnerAssert(obj != null, callerName, callerLine, callerFile);
        }

        [AssertionMethod]
        public static void Assert([AssertionCondition(AssertionConditionType.IS_TRUE)] bool condition, [CallerMemberName] string? callerName = null, [CallerLineNumber] int callerLine = 0, [CallerFilePath] string? callerFile = null)
        {
            InnerAssert(condition, callerName, callerLine, callerFile);
        }

        [AssertionMethod]
        private static void InnerAssert([AssertionCondition(AssertionConditionType.IS_TRUE)]bool condition, string? callerName, int callerLine, string? callerFile)
        {
            if (condition) return;

            throw new SecurityException($"Failed security assertion in '{callerName}' - {callerFile}:{callerLine}");
        }

        [AssertionMethod]
        public static void AssertHash(byte[]? a, byte[]? b, [CallerMemberName] string? callerName = null, [CallerLineNumber] int callerLine = 0, [CallerFilePath] string? callerFile = null)
        {
            InnerAssert(a != null, callerName, callerLine, callerFile);
            InnerAssert(b != null, callerName, callerLine, callerFile);

            InnerAssert(BufferUtils.EqualConstantTime(a!, b!), callerName, callerLine, callerFile);
        }

        [AssertionMethod]
        public static void AssertBuffer(byte[]? buffer, int offset, int length, [CallerMemberName] string? callerName = null, [CallerLineNumber] int callerLine = 0, [CallerFilePath] string? callerFile = null)
        {
            InnerAssert(buffer != null, callerName, callerLine, callerFile);

            InnerAssert(offset >= 0, callerName, callerLine, callerFile);
            InnerAssert(length >= 0, callerName, callerLine, callerFile);
            InnerAssert(offset + length <= buffer!.Length, callerName, callerLine, callerFile);
        } 
        [AssertionMethod]
        public static void AssertBuffer<T>(ReadOnlySpan<T> buffer, int length, [CallerMemberName] string? callerName = null, [CallerLineNumber] int callerLine = 0, [CallerFilePath] string? callerFile = null)
        {
            InnerAssert(buffer != null, callerName, callerLine, callerFile);

            InnerAssert(length >= 0, callerName, callerLine, callerFile);
            InnerAssert( length <= buffer!.Length, callerName, callerLine, callerFile);
        }
        [AssertionMethod]
        public static void AssertBuffer<T>(Span<T> buffer, int length, [CallerMemberName] string? callerName = null, [CallerLineNumber] int callerLine = 0, [CallerFilePath] string? callerFile = null)
        {
            InnerAssert(buffer != null, callerName, callerLine, callerFile);

            InnerAssert(length >= 0, callerName, callerLine, callerFile);
            InnerAssert( length <= buffer!.Length, callerName, callerLine, callerFile);
        }
        
        [AssertionMethod]
        public static void AssertInputOutputBuffers(ReadOnlySpan<byte> input, Span<byte> output, [CallerMemberName] string? callerName = null, [CallerLineNumber] int callerLine = 0, [CallerFilePath] string? callerFile = null)
        {
            AssertInputOutputBuffers(input, output, input.Length, callerName, callerLine, callerFile);
        }
        [AssertionMethod]
        public static void AssertInputOutputBuffers(ReadOnlySpan<byte> input, Span<byte> output, int length, [CallerMemberName] string? callerName = null, [CallerLineNumber] int callerLine = 0, [CallerFilePath] string? callerFile = null)
        {
            InnerAssert(input.Length >= length, callerName, callerLine, callerFile);
            InnerAssert(output.Length >= length, callerName, callerLine, callerFile);
        }
    }
}
