using StandardCore.Security.PasswordHasher;
using StandardCore.Security.PasswordHasher.BinaryConverter;
using StandardCore.Security.PasswordHasher.Hasher;
using StandardCore.Security.PasswordHasher.RandomGenerator;
using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace PasswordHasherUnitTest
{
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

        [Fact]
        public void Pbkdf2WthBase64()
        {
            var passwordHasher = new PasswordHasher(binaryConverter, secureRandomGenerator, passwordFormatHashers);
            var hashedPassword = passwordHasher.HashPassword(TestPassword, FormatMarkers.Pbkdf2);
            var flag = passwordHasher.VerifyHashedPassword(hashedPassword, TestPassword);
            Assert.True(flag);
        }

        [Fact]
        public void Aes256WithBase64()
        {
            var passwordHasher = new PasswordHasher(binaryConverter, secureRandomGenerator, passwordFormatHashers);
            var hashedPassword = passwordHasher.HashPassword(TestPassword, FormatMarkers.Aes256);
            var flag = passwordHasher.VerifyHashedPassword(hashedPassword, TestPassword);
            Assert.True(flag);
        }
    }
}
