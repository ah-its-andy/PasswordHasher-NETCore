using Microsoft.VisualStudio.TestTools.UnitTesting;
using StandardCore.Security.PasswordHasher;
using StandardCore.Security.PasswordHasher.BinaryConverter;
using System.Text;

namespace PasswordHasherTest
{
    [TestClass]
    public class BinaryConvertTests
    {
        private static readonly byte[] TestInput = Encoding.UTF8.GetBytes("1234567890-=!@#$%^&*()_ASJKLFDJKLdsjakdjklasjkdla");

        [TestMethod]
        public void Base64()
        {
            var converter = new Base64BinaryConverter();
            var str = converter.GetString(TestInput);
            var bytes = converter.GetBytes(str);
            var flag = BufferUtil.ByteArraysEqual(TestInput, bytes);
            Assert.IsTrue(flag);
        }
    }
}
