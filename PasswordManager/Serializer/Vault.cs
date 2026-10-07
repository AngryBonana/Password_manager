using System.Collections;
using System.Security.Cryptography;

namespace Serializer;

public sealed class Vault : IEnumerable<VaultEntry>, IDisposable
{
    private readonly List<VaultEntry> _entries = new();

    public int Length => _entries.Count;

    public Vault() { }

    public Vault(IEnumerable<VaultEntry> entries)
    {
        _entries.AddRange(entries ?? Enumerable.Empty<VaultEntry>());
    }

    public void AddVaultEntry(VaultEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        _entries.Add(entry);
    }

    public bool CheckExistance(byte[] serviceName)
        => FindEntry(serviceName) is not null;

    public VaultEntry? FindEntry(byte[] serviceName)
    {
        ArgumentNullException.ThrowIfNull(serviceName);
        foreach (var entry in _entries)
        {
            if (entry.ServiceName.AsSpan().SequenceEqual(serviceName))
                return entry;
        }
        return null;
    }

    public bool ChangeEntry(
        byte[] serviceName,
        byte[]? login = null,
        byte[]? password = null,
        byte[]? addInfo = null)
    {
        var changing = FindEntry(serviceName);
        if (changing is null)
            return false;

        if (login is not null) changing.Login = login;
        if (password is not null) changing.Password = password;
        if (addInfo is not null) changing.AdditionalInfo = addInfo;

        return true;
    }

    public bool DeleteEntry(byte[] serviceName)
    {
        var entry = FindEntry(serviceName);
        if (entry is null)
            return false;

        entry.ClearVaultEntry();
        _entries.Remove(entry);
        return true;
    }

    public IEnumerator<VaultEntry> GetEnumerator() => _entries.GetEnumerator();
    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    public void Dispose()
    {
        foreach (var entry in _entries)
            entry.ClearVaultEntry();
        _entries.Clear();
    }
}