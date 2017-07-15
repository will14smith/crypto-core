using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using Crypto.Utils;

namespace Crypto.Core.Randomness
{
    public static class RandomPrimeExtensions
    {
        private static readonly List<int> SmallPrimes;

        static RandomPrimeExtensions()
        {
            SmallPrimes = SievePrimes(1000000);
        }

        public static BigInteger RandomBigPrime(this IRandom random, int bits)
        {
            SecurityAssert.Assert(bits > 2);

            BigInteger value;
            do
            {
                value = random.RandomBig(bits);
                // make sure it is odd
                value |= 1;

                // k = 50, P(not prime) = 2^-100
            } while (!IsProbablyPrime(random, value, 50));

            return value;
        }

        private static List<int> SievePrimes(int max)
        {
            SecurityAssert.Assert(max > 1);

            var maxSqrt = (int)Math.Ceiling(Math.Sqrt(max));
            var a = new BitArray(max + 1, true);

            for (var i = 2; i < maxSqrt; i++)
            {
                if (a[i])
                {
                    var j = i * i;
                    while (j <= max)
                    {
                        a[j] = false;
                        j += i;
                    }
                }
            }

            var list = new List<int>();

            for (var i = 2; i <= max; i++)
            {
                if (a[i])
                {
                    list.Add(i);
                }
            }

            return list;
        }

        private static bool IsProbablyPrime(IRandom random, BigInteger n, int k)
        {
            // preselection using small primes
            if (SmallPrimes.Any(p => n % p == 0))
            {
                return false;
            }

            // n - 1 = 2^r * d;
            var r = 0;
            var d = n - 1;
            while (d % 2 == 0)
            {
                r++;
                d /= 2;
            }

            for (var i = 0; i < k; i++)
            {
                // a = random [2, n-2]
                var a = random.RandomBig(n - 4) + 2;

                var x = BigInteger.ModPow(a, d, n);
                if (x == 1 || x == n - 1) { continue; }

                for (var j = 1; j < r; j++)
                {
                    x = BigInteger.ModPow(x, 2, n);

                    if (x == 1)
                    {
                        return false;
                    }

                    if (x == n - 1)
                    {
                        break;
                    }
                }

                if (x != n - 1)
                {
                    return false;
                }
            }

            return true;
        }

    }
}