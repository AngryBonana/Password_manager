using System.Security.Cryptography;
using System.Text;

namespace Serializer;

public sealed class VaultEntry : IDisposable
{
    private byte[] _password = Array.Empty<byte>();
    private byte[] _serviceName = Array.Empty<byte>();
    private byte[] _login = Array.Empty<byte>();
    private byte[] _additionalInfo = Array.Empty<byte>();

    public byte[] Password
    {
        get => _password;
        set
        {
            CryptographicOperations.ZeroMemory(_password);
            _password = value is null ? Array.Empty<byte>() : (byte[])value.Clone();
        }
    }

    public byte[] ServiceName
    {
        get => _serviceName;
        set
        {
            CryptographicOperations.ZeroMemory(_serviceName);
            _serviceName = value is null ? Array.Empty<byte>() : (byte[])value.Clone();
        }
    }

    public byte[] Login
    {
        get => _login;
        set
        {
            CryptographicOperations.ZeroMemory(_login);
            _login = value is null ? Array.Empty<byte>() : (byte[])value.Clone();
        }
    }

    public byte[] AdditionalInfo
    {
        get => _additionalInfo;
        set
        {
            CryptographicOperations.ZeroMemory(_additionalInfo);
            _additionalInfo = value is null ? Array.Empty<byte>() : (byte[])value.Clone();
        }
    }

    public string GetPasswordString() => Encoding.UTF8.GetString(_password);
    public string GetServiceNameString() => Encoding.UTF8.GetString(_serviceName);
    public string GetLoginString() => Encoding.UTF8.GetString(_login);
    public string GetAdditionalInfoString() => Encoding.UTF8.GetString(_additionalInfo);

    public void ClearPassword() => ZeroAndReset(ref _password);
    public void ClearServiceName() => ZeroAndReset(ref _serviceName);
    public void ClearLogin() => ZeroAndReset(ref _login);
    public void ClearAdditionalInfo() => ZeroAndReset(ref _additionalInfo);

    public void ClearVaultEntry()
    {
        ClearPassword();
        ClearServiceName();
        ClearLogin();
        ClearAdditionalInfo();
    }

    public void Dispose() => ClearVaultEntry();

    private static void ZeroAndReset(ref byte[] field)
    {
        CryptographicOperations.ZeroMemory(field);
        field = Array.Empty<byte>();
    }
}