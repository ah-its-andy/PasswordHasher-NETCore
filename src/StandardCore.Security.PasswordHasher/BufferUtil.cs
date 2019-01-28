using System;
using System.Runtime.CompilerServices;

namespace StandardCore.Security.PasswordHasher
{
    internal static class BufferUtil
    {
        internal static void WriteNetworkByteOrder(byte[] buffer, int offset, uint value)
        {
            buffer[offset + 0] = (byte)(value >> 24);
            buffer[offset + 1] = (byte)(value >> 16);
            buffer[offset + 2] = (byte)(value >> 8);
            buffer[offset + 3] = (byte)(value >> 0);
        }

        internal static uint ReadNetworkByteOrder(byte[] buffer, int offset)
        {
            return ((uint)buffer[offset + 0] << 24)
                   | ((uint)buffer[offset + 1] << 16)
                   | ((uint)buffer[offset + 2] << 8)
                   | buffer[offset + 3];
        }

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        internal static bool ByteArraysEqual(byte[] a, byte[] b)
        {
            if (a == null && b == null)
                return true;
            if (a == null || b == null || a.Length != b.Length)
                return false;
            var areSame = true;
            for (var i = 0; i < a.Length; i++)
                areSame &= a[i] == b[i];
            return areSame;
        }

        internal static void BlockFill(Array src, Array dest, int offset)
        {
            Buffer.BlockCopy(src, 0, dest, offset, src.Length);
        }
    }
}
