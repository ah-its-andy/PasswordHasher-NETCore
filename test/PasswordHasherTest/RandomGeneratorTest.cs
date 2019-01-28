using Microsoft.VisualStudio.TestTools.UnitTesting;
using StandardCore.Routine;
using StandardCore.Security.PasswordHasher;
using StandardCore.Security.PasswordHasher.RandomGenerator;
using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Threading;

namespace PasswordHasherTest
{
    [TestClass]
    public class RandomGeneratorTest
    {
        [TestMethod]
        public void TestSecureRandomGenerator()
        {
            var results = new ConcurrentBag<byte[]>();
            var wg = new WaitGroup();
            for (int i = 0; i < 10000; i++)
            {
                wg.Add(1);
                ThreadPool.QueueUserWorkItem(state => 
                {
                    results.Add(new SecureRandomGenerator().GenerateBytes(32));
                    wg.Done();
                });
            }
            wg.Await();
            Assert.IsTrue(results.Any());
            var flag = results.Select(x => new EqualableBinary(x))
                .GroupBy(x => x)
                .Any(x => x.Count() > 1);
            Assert.IsFalse(flag);
        }

        private class EqualableBinary : IEquatable<byte[]>
        {
            private readonly byte[] _source;

            public EqualableBinary(byte[] source)
            {
                _source = source ?? throw new ArgumentNullException(nameof(source));
            }

            public bool Equals(byte[] other)
            {
                return BufferUtil.ByteArraysEqual(_source, other);
            }

            public override bool Equals(object obj)
            {
                if(obj is EqualableBinary equalableBinary)
                {
                    return Equals(equalableBinary._source);
                }
                if(obj is byte[] bytes)
                {
                    return Equals(bytes);
                }
                return false;
            }

            public override int GetHashCode()
            {
                return HashCode.Combine(_source);
            }
        }
    }
}
