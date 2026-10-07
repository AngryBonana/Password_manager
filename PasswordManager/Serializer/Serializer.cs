using System.Buffers.Binary;
using System.Text;

namespace Serializer;

public static class VaultSerializer
{
    private const int MaxFieldSize = 16 * 1024 * 1024; // 16 MiB — защита от мусора в файле


    public static Vault Serialize(ReadOnlySpan<byte> data)
    {
        var vault = new Vault();
        int offset = 0;

        while (offset < data.Length)
        {
            byte[] serviceName = ReadField(data, ref offset);
            byte[] login       = ReadField(data, ref offset);
            byte[] password    = ReadField(data, ref offset);
            byte[] addInfo     = ReadField(data, ref offset);

            var entry = new VaultEntry
            {
                ServiceName = serviceName,
                Login = login,
                Password = password,
                AdditionalInfo = addInfo,
            };
            vault.AddVaultEntry(entry);

            System.Security.Cryptography.CryptographicOperations.ZeroMemory(serviceName);
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(login);
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(password);
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(addInfo);
        }

        return vault;
    }


    public static byte[] Deserialize(Vault vault)
    {
        ArgumentNullException.ThrowIfNull(vault);

        long totalSize = 0;
        foreach (var entry in vault)
        {
            totalSize += 4 + entry.ServiceName.Length;
            totalSize += 4 + entry.Login.Length;
            totalSize += 4 + entry.Password.Length;
            totalSize += 4 + entry.AdditionalInfo.Length;
        }

        if (totalSize > int.MaxValue)
            throw new InvalidOperationException("Vault is too large to serialize");

        byte[] result = new byte[(int)totalSize];
        int offset = 0;

        foreach (var entry in vault)
        {
            WriteField(result, ref offset, entry.ServiceName);
            WriteField(result, ref offset, entry.Login);
            WriteField(result, ref offset, entry.Password);
            WriteField(result, ref offset, entry.AdditionalInfo);
        }

        return result;
    }


    private static byte[] ReadField(ReadOnlySpan<byte> data, ref int offset)
    {
        if (offset + 4 > data.Length)
            throw new InvalidDataException("Corrupted vault: truncated length");

        int length = BinaryPrimitives.ReadInt32LittleEndian(data[offset..]);
        offset += 4;

        if (length < 0 || length > MaxFieldSize)
            throw new InvalidDataException($"Corrupted vault: invalid field length {length}");

        if (offset + length > data.Length)
            throw new InvalidDataException("Corrupted vault: truncated field data");

        byte[] result = data.Slice(offset, length).ToArray();
        offset += length;
        return result;
    }

    private static void WriteField(byte[] target, ref int offset, byte[] value)
    {
        BinaryPrimitives.WriteInt32LittleEndian(target.AsSpan(offset), value.Length);
        offset += 4;

        value.CopyTo(target.AsSpan(offset));
        offset += value.Length;
    }
}