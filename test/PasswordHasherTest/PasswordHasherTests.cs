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
        private const string Pbkdf2Compatibility = "AQAAAAEAACcQAAAAELJDOTDL/u80qJGRkZbmncbo/pEM+f9BRFSikvHvUZPem/GlJ5E8J4fbih3yoU+54w==";
        private const string Aes256Compatibility = "AgAAAAIAAAABbUaexCPOHjeIFtOw8DNefLq7BQR6gHSodyfCCyzTARpKJfXEJRMnev7NnVnO5ipHLKUr2cegnQ0bzlEUrRXksVS5O/vYhJix5YQ5FLTt85wflKD08NfC/Z8kCC52xtMz";
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
        public void Pbkdf2WithBase64Compatibility()
        {
            var passwordHasher = new PasswordHasher(binaryConverter, secureRandomGenerator, passwordFormatHashers);
            var flag = passwordHasher.VerifyHashedPassword(Pbkdf2Compatibility, TestPassword);
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

        [TestMethod]
        public void Aes256WithBase64Compatibility()
        {
            var passwordHasher = new PasswordHasher(binaryConverter, secureRandomGenerator, passwordFormatHashers);
            var flag = passwordHasher.VerifyHashedPassword(Aes256Compatibility, TestPassword);
            Assert.IsTrue(flag);
        }
    }
}
