using Konscious.Security.Cryptography;
using System.Security.Cryptography;


namespace Crypto;

public class PasswordHasher
{
    
    public const int StoredHashSize = _hashSize + _saltSize;
    private const int _saltSize = 16;
    private const int _hashSize = 32;

    private const int _memorySizeKb = 1 << 16; // 64 Mb

    private const int _iterations = 3; 
    private const int _threads = 1;

    public static (byte[], byte[]) GenerateNewHashPassword(byte[] password)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(_saltSize);
        var argon2 = new Argon2id(password)
        {
            Salt = salt,
            DegreeOfParallelism = _threads,
            Iterations = _iterations,
            MemorySize = _memorySizeKb
        };

        byte[] derived = argon2.GetBytes(_hashSize * 2);

        byte[] encryptionHash = derived[0.._hashSize];

        byte[] storedHash = new byte[_hashSize + _saltSize];
        Buffer.BlockCopy(derived, _hashSize, storedHash, 0, _hashSize);
        Buffer.BlockCopy(salt, 0, storedHash, _hashSize, _saltSize);
        CryptographicOperations.ZeroMemory(derived);
        return (encryptionHash, storedHash);
    }


    public static byte[]? TryUnlock(byte[] password, byte[] storedHash)
    {
        ArgumentNullException.ThrowIfNull(storedHash);
        if (storedHash.Length != StoredHashSize)
            throw new ArgumentException($"Incorrect size of stored hash {storedHash.Length} instead of {StoredHashSize}!");

        byte[] salt = new byte[_saltSize];
        byte[] verifyHash = new byte[_hashSize];
        Buffer.BlockCopy(storedHash, 0, verifyHash, 0, _hashSize);
        Buffer.BlockCopy(storedHash, _hashSize, salt, 0, _saltSize);

        var argon = new Argon2id(password)
        {
            Salt = salt,
            Iterations = _iterations,
            MemorySize = _memorySizeKb,
            DegreeOfParallelism = _threads
        };

        byte[] derived = argon.GetBytes(_hashSize * 2);
        
        byte[] countedVerifyHash = derived[_hashSize..];

        if (CryptographicOperations.FixedTimeEquals(countedVerifyHash, verifyHash))
        {
            byte[] encryptionKey = derived[0.._hashSize];
            CryptographicOperations.ZeroMemory(derived);
            return encryptionKey;
        }

        CryptographicOperations.ZeroMemory(derived);
        return null;
    }

}