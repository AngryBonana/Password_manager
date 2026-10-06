using System.Collections;
using System.Security.Cryptography;
using System.Text;


namespace Serializer;

public sealed class VaultEntry
{
    private byte[] _password = Array.Empty<byte>();
    private byte[] _serviceName = Array.Empty<byte>();
    private byte[] _login = Array.Empty<byte>();
    private byte[] _additionalInfo = Array.Empty<byte>();
    public byte[] Password
    {
        get => _password;
        set => _password = value ?? Array.Empty<byte>();
    }

    public byte[] ServiceName
    {
        get => _serviceName;
        set => _serviceName = value ?? Array.Empty<byte>();
    }

    public byte[] Login
    {
        get => _login;
        set => _login = value ?? Array.Empty<byte>();
    }

    public byte[] AdditionalInfo
    {
        get => _additionalInfo;
        set => _additionalInfo = value ?? Array.Empty<byte>();
    }
    public string GetPasswordString() => Encoding.UTF8.GetString(_password);

    public void ClearPassword() => CryptographicOperations.ZeroMemory(_password);

    public string GetServiceNameString() => Encoding.UTF8.GetString(_serviceName);

    public void ClearServiceName() => CryptographicOperations.ZeroMemory(_serviceName);

    public string GetLoginString() => Encoding.UTF8.GetString(_login);

    public void ClearLogin() => CryptographicOperations.ZeroMemory(_login);

    public string GetAdditionalInfoString() => Encoding.UTF8.GetString(_additionalInfo);

    public void ClearAdditionalInfo() => CryptographicOperations.ZeroMemory(_additionalInfo);

    public void ClearVaultEntry()
    {
        ClearPassword();
        ClearLogin();
        ClearAdditionalInfo();
        ClearServiceName();
    }
}

public sealed class Vault
{
    private VaultEntry[] _entries;

    public int Length {get {return _entries.Length;}} 

    public Vault()
    {
        _entries = Array.Empty<VaultEntry>();
    }
    public Vault(VaultEntry[] entries)
    {
        _entries = entries ?? Array.Empty<VaultEntry>();
    }

    ~Vault()
    {
        foreach (var i in _entries)
        {
            i.ClearVaultEntry();
        }
    }

    public void AddVaultEntry(VaultEntry newVault)
    {
        _entries.Append(newVault);
    }

    public IEnumerator<VaultEntry> GetEnumerator()
    {
        foreach (VaultEntry i in _entries)
        {
            yield return i;
        }
    }
}

public sealed class Serializer
{
    public static Vault Serialize(byte[] data)
    {
        Vault vault = new Vault();
        for (int i = 0; i < data.Length; ++i)
        {
            
        }

        return vault;    
    }

    public static byte[] Deserialize(Vault data)
    {
        byte[] deserializedArray = [];

        foreach (var i in data)
        {
            byte[] servNameLength = BitConverter.GetBytes(i.ServiceName.Length);
            byte[] loginLength = BitConverter.GetBytes(i.Login.Length);
            byte[] passwordLength = BitConverter.GetBytes(i.Password.Length);
            byte[] addInfoLength = BitConverter.GetBytes(i.AdditionalInfo.Length);

            deserializedArray.Concat(servNameLength);
            deserializedArray.Concat(i.ServiceName);
            deserializedArray.Concat(loginLength);
            deserializedArray.Concat(i.Login);
            deserializedArray.Concat(passwordLength);
            deserializedArray.Concat(i.Password);
            deserializedArray.Concat(addInfoLength);
            deserializedArray.Concat(i.AdditionalInfo);
            CryptographicOperations.ZeroMemory(servNameLength);
            CryptographicOperations.ZeroMemory(passwordLength);
            CryptographicOperations.ZeroMemory(loginLength);
            CryptographicOperations.ZeroMemory(addInfoLength);
        }

        return deserializedArray;
    } 

}
