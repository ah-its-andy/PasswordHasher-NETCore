using Microsoft.VisualStudio.TestTools.UnitTesting;
using StandardCore.Security.PasswordHasher;
using StandardCore.Security.PasswordHasher.BinaryConverter;
using StandardCore.Security.PasswordHasher.Hasher;
using StandardCore.Security.PasswordHasher.RandomGenerator;
using System.Collections.Generic;

namespace PasswordHasherTest
{
    [TestClass]
    public class PasswordHasherTests
    {
        private const string TestPassword = "TestPassword1234567890!@#$%^*&(()(__)";
        private static readonly IEnumerable<IPasswordFormatHasher> passwordFormatHashers
            = new List<IPasswordFormatHasher>
            {
                new Pbkdf2PasswordHasher(),
                new Aes256PasswordHasher()
            };
        private static readonly IBinaryConverter binaryConverter = new Base64BinaryConverter();
        private static readonly ISecureRandomGenerator secureRandomGenerator = new SecureRandomGenerator();

        [TestMethod]
        public void Pbkdf2WthBase64()
        {
            var passwordHasher = new PasswordHasher(binaryConverter, secureRandomGenerator, passwordFormatHashers);
            var hashedPassword = passwordHasher.HashPassword(TestPassword, FormatMarkers.Pbkdf2);
            var flag = passwordHasher.VerifyHashedPassword(hashedPassword, TestPassword);
            Assert.IsTrue(flag);
        }

        [TestMethod]
        public void Aes256WithBase64()
        {
            var passwordHasher = new PasswordHasher(binaryConverter, secureRandomGenerator, passwordFormatHashers);
            var hashedPassword = passwordHasher.HashPassword(TestPassword, FormatMarkers.Aes256);
            var flag = passwordHasher.VerifyHashedPassword(hashedPassword, TestPassword);
            Assert.IsTrue(flag);
        }
    }
}
