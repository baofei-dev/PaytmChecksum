using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Security.Cryptography;

public static class PaytmChecksum
{
    private const string IV = "@@@@&&&&####$$$$";
    private static readonly Random RANDOM = new Random();

    public static string Encrypt(string input, string key)
    {
        byte[] bytesToBeEncrypted = Encoding.UTF8.GetBytes(input);
        byte[] passwordBytes = Encoding.UTF8.GetBytes(key);
        byte[] ivBytes = Encoding.UTF8.GetBytes(IV);
        byte[] encryptedBytes = null;
        using var ms = new MemoryStream();
        using var AES = new RijndaelManaged();
        AES.KeySize = 256;
        AES.BlockSize = 128;
        AES.Key = passwordBytes;
        AES.IV = ivBytes;
        AES.Mode = CipherMode.CBC;
        using var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write);
        cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
        cs.Close();
        encryptedBytes = ms.ToArray();
        return Convert.ToBase64String(encryptedBytes);
    }

    public static string Decrypt(string encrypted, string key)
    {
        byte[] bytesToBeDecrypted = Convert.FromBase64String(encrypted);
        byte[] passwordBytes = Encoding.UTF8.GetBytes(key);
        byte[] ivBytes = Encoding.UTF8.GetBytes(IV);
        byte[] decryptedBytes = null;
        using var ms = new MemoryStream();
        using var AES = new RijndaelManaged();
        AES.KeySize = 256;
        AES.BlockSize = 128;
        AES.Key = passwordBytes;
        AES.IV = ivBytes;
        AES.Mode = CipherMode.CBC;
        using var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write);
        cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
        cs.Close();
        decryptedBytes = ms.ToArray();
        return Encoding.Default.GetString(decryptedBytes);
    }

    public static string GenerateSignature(Dictionary<string, string> paramters, string key)
    {
        return GenerateSignature(GetStringByParameters(paramters), key);
    }

    public static string GenerateSignature(string parameters, string key)
    {
        var salt = GenerateRandomString(4);
        return CalculateCheecksum(parameters, key, salt);
    }

    public static bool VerifySignature(Dictionary<string, string> parameters, string key, string checksum)
    {
        if (parameters.ContainsKey("CHECKSUMHASH"))
        {
            parameters.Remove("CHECKSUMHASH");
        }
        return VerifySignature(GetStringByParameters(parameters), key, checksum);
    }

    public static bool VerifySignature(string parameters, string key, string checksum)
    {
        var hashStr = Decrypt(checksum, key);
        var salt = hashStr.Substring(hashStr.Length - 4);
        return hashStr == CalculateHash(parameters, salt);
    }

    public static string GenerateRandomString(int length)
    {
        var randomBytes = new byte[(length * 3) / 4];
        for (var i = 0; i < randomBytes.Length; i++)
        {
            randomBytes[i] = (byte)RANDOM.Next(0, 256);
        }
        return Convert.ToBase64String(randomBytes);
    }

    public static string GetStringByParameters(Dictionary<string, string> paramters)
    {
        var keys = new List<string>(paramters.Keys);
        keys.Sort();
        var strBuilder = new StringBuilder();
        foreach (var key in keys)
        {
            strBuilder.Append(paramters[key] + "|");
        }
        strBuilder.Remove(strBuilder.Length - 1, 1);
        return strBuilder.ToString();
    }

    public static string CalculateHash(string paramters, string salt)
    {
        var finalString = paramters + "|" + salt;
        using var sha256 = new SHA256CryptoServiceProvider();
        var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(finalString));
        return BitConverter.ToString(hashBytes).Replace("-", "").ToLower() + salt;
    }

    public static string CalculateCheecksum(string paramters, string key, string salt)
    {
        var hashStr = CalculateHash(paramters, salt);
        return Encrypt(hashStr, key);
    }
}
