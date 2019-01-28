using System;
using System.Security.Cryptography;
using System.Text;

namespace StandardCore.Security.PasswordHasher.Hasher
{
    public class Aes256PasswordHasher : IPasswordFormatHasher
    {
        public bool Supported(byte formatMarker) => formatMarker == FormatMarkers.Aes256;

        public byte[] HashPassword(string password, ISecureRandomGenerator secureRandomGenerator)
        {
            var passwordBytes = Encoding.UTF8.GetBytes(password);
            var salt = secureRandomGenerator.GenerateBytes(32);
            var iv = secureRandomGenerator.GenerateBytes(16);

            var cipher = Aes.Create();
            cipher.KeySize = 256;
            cipher.Padding = PaddingMode.PKCS7;
            cipher.Mode = CipherMode.CBC;
            cipher.Key = salt;
            cipher.IV = iv;
            var encryptor = cipher.CreateEncryptor();
            var subKey = encryptor.TransformFinalBlock(passwordBytes, 0, passwordBytes.Length);

            var outputBytes = new byte[9 + salt.Length + iv.Length + subKey.Length];
            outputBytes[0] = FormatMarkers.Aes256;
            BufferUtil.WriteNetworkByteOrder(outputBytes, 1, (uint)cipher.Padding);
            BufferUtil.WriteNetworkByteOrder(outputBytes, 5, (uint)cipher.Mode);
            BufferUtil.BlockFill(salt, outputBytes, 9);
            BufferUtil.BlockFill(iv, outputBytes, 9 + salt.Length);
            BufferUtil.BlockFill(subKey, outputBytes, 9 + salt.Length + iv.Length);
            return outputBytes;
        }

        public bool VerifyHashedPassword(byte[] decodedHashedPassword, string providedPassword)
        {
            var paddingMode = (PaddingMode)BufferUtil.ReadNetworkByteOrder(decodedHashedPassword, 1);
            var cipherMode = (CipherMode)BufferUtil.ReadNetworkByteOrder(decodedHashedPassword, 5);

            var salt = new byte[32];
            Buffer.BlockCopy(decodedHashedPassword, 9, salt, 0, salt.Length);
            var iv = new byte[16];
            Buffer.BlockCopy(decodedHashedPassword, 9 + salt.Length, iv, 0, iv.Length);
            var expectedKey = new byte[decodedHashedPassword.Length - salt.Length - iv.Length - 9];
            Buffer.BlockCopy(decodedHashedPassword, 9 + salt.Length + iv.Length, expectedKey, 0, expectedKey.Length);

            var cipher = Aes.Create();
            cipher.KeySize = 256;
            cipher.Padding = paddingMode;
            cipher.Mode = cipherMode;
            cipher.Key = salt;
            cipher.IV = iv;

            var decryptor = cipher.CreateDecryptor();
            var expectedPasswordBytes = decryptor.TransformFinalBlock(expectedKey, 0, expectedKey.Length);
            var expectedPassword = Encoding.UTF8.GetString(expectedPasswordBytes);
            return providedPassword.Equals(expectedPassword);
        }
    }
}
