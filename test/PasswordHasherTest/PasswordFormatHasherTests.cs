using Microsoft.VisualStudio.TestTools.UnitTesting;
using StandardCore.Security.PasswordHasher.Hasher;
using StandardCore.Security.PasswordHasher.RandomGenerator;

namespace PasswordHasherTest
{
    [TestClass]
    public class PasswordFormatHasherTests
    {
        private const string TestPassword = "TestPassword1234567890!@#$%^*&(()(__)";

        [TestMethod]
        public void Pbkdf2()
        {
            var hasher = new Pbkdf2PasswordHasher();
            var hashedPassword = hasher.HashPassword(TestPassword, new SecureRandomGenerator());
            Assert.IsNotNull(hashedPassword);
            var flag = hasher.VerifyHashedPassword(hashedPassword, TestPassword);
            Assert.IsTrue(flag);
        }

        [TestMethod]
        public void Aes256()
        {
            var hasher = new Aes256PasswordHasher();
            var hashedPassword = hasher.HashPassword(TestPassword, new SecureRandomGenerator());
            Assert.IsNotNull(hashedPassword);
            var flag = hasher.VerifyHashedPassword(hashedPassword, TestPassword);
            Assert.IsTrue(flag);
        }
    }
}
