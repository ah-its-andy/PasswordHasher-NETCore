using StandardCore.Security.PasswordHasher.BinaryConverter;
using StandardCore.Security.PasswordHasher.Hasher;
using StandardCore.Security.PasswordHasher.RandomGenerator;
using Xunit;

namespace PasswordHasherUnitTest
{
    public class PasswordFormatHasherTests
    {
        private const string TestPassword = "TestPassword1234567890!@#$%^*&(()(__)";

        [Fact]
        public void Pbkdf2()
        {
            var hasher = new Pbkdf2PasswordHasher();
            var hashedPassword = hasher.HashPassword(TestPassword, new SecureRandomGenerator());
            Assert.NotNull(hashedPassword);
            var flag = hasher.VerifyHashedPassword(hashedPassword, TestPassword);
            Assert.True(flag);
        }

        [Fact]
        public void Aes256()
        {
            var hasher = new Aes256PasswordHasher();
            var hashedPassword = hasher.HashPassword(TestPassword, new SecureRandomGenerator());
            Assert.NotNull(hashedPassword);
            var flag = hasher.VerifyHashedPassword(hashedPassword, TestPassword);
            Assert.True(flag);
        }
    }
}
