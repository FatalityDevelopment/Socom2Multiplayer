namespace CodeDesigner.Ps2.Multiplayer.Dnas;

    /// <summary>Central entry points for recovered, original DNAS cryptography.</summary>
    public static class Cryptography
    {
        public static byte[] DesEncrypt(byte[] data, byte[] key8, byte[]? iv8 = null) => DES.Encrypt(data, key8, iv8);
        public static byte[] DesDecrypt(byte[] data, byte[] key8, byte[]? iv8 = null) => DES.Decrypt(data, key8, iv8);
        public static byte[] TripleDesEncrypt(byte[] data, byte[] key24, byte[]? iv8 = null) => DES.Encrypt3(data, key24, iv8);
        public static byte[] TripleDesDecrypt(byte[] data, byte[] key24, byte[]? iv8 = null) => DES.Decrypt3(data, key24, iv8);
        public static byte[] RsaPublicOperation(byte[] operand128, byte[] modulus128, int exponent = Public.RsaExponent) => RSA.PublicOperation(operand128, modulus128, exponent);
        public static byte[] VerifyServerTicket(byte[] signedOperand128, byte[] modulus128) => RSA.VerifyServerOperand(signedOperand128, modulus128);
    }
