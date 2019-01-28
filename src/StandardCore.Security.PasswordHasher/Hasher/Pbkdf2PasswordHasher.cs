using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System;

namespace StandardCore.Security.PasswordHasher.Hasher
{
    public class Pbkdf2PasswordHasher : IPasswordFormatHasher
    {
        private const int IterCount = 10000;

        public bool Supported(byte formatMarker) => formatMarker == FormatMarkers.Pbkdf2;

        public byte[] HashPassword(string password, ISecureRandomGenerator secureRandomGenerator)
        {
            return HashPasswordByPkbdf2(password, secureRandomGenerator, KeyDerivationPrf.HMACSHA256, IterCount, 128 / 8, 256 / 8);
        }

        public bool VerifyHashedPassword(byte[] decodedHashedPassword, string providedPassword)
        {
            // Read header information
            var prf = (KeyDerivationPrf)BufferUtil.ReadNetworkByteOrder(decodedHashedPassword, 1);
            var iterCount = (int)BufferUtil.ReadNetworkByteOrder(decodedHashedPassword, 5);
            var saltLength = (int)BufferUtil.ReadNetworkByteOrder(decodedHashedPassword, 9);

            // Read the salt: must be >= 128 bits
            if (saltLength < 128 / 8)
            {
                return false;
            }
            var salt = new byte[saltLength];
            Buffer.BlockCopy(decodedHashedPassword, 13, salt, 0, salt.Length);

            // Read the subkey (the rest of the payload): must be >= 128 bits
            var subkeyLength = decodedHashedPassword.Length - 13 - salt.Length;
            if (subkeyLength < 128 / 8)
            {
                return false;
            }
            var expectedSubkey = new byte[subkeyLength];
            Buffer.BlockCopy(decodedHashedPassword, 13 + salt.Length, expectedSubkey, 0, expectedSubkey.Length);

            // Hash the incoming password and verify it
            var actualSubKey = KeyDerivation.Pbkdf2(providedPassword, salt, prf, iterCount, subkeyLength);

            return iterCount > 0 && BufferUtil.ByteArraysEqual(actualSubKey, expectedSubkey);
        }

        #region Pkbdf2 Static Methods
        private static byte[] HashPasswordByPkbdf2(string password, ISecureRandomGenerator secureRandomGenerator, KeyDerivationPrf keyDerivationPrf, int iterCount, uint saltSize, int numBytesRequested)
        {
            var salt = secureRandomGenerator.GenerateBytes(saltSize);
            var subkey = KeyDerivation.Pbkdf2(password, salt, keyDerivationPrf, iterCount, numBytesRequested);

            var outputBytes = new byte[13 + salt.Length + subkey.Length];
            outputBytes[0] = FormatMarkers.Pbkdf2; // format marker
            BufferUtil.WriteNetworkByteOrder(outputBytes, 1, (uint)keyDerivationPrf);
            BufferUtil.WriteNetworkByteOrder(outputBytes, 5, (uint)iterCount);
            BufferUtil.WriteNetworkByteOrder(outputBytes, 9, (uint)saltSize);
            Buffer.BlockCopy(salt, 0, outputBytes, 13, salt.Length);
            Buffer.BlockCopy(subkey, 0, outputBytes, 13 + (int)saltSize, subkey.Length);
            return outputBytes;
        }
        #endregion
    }
}
