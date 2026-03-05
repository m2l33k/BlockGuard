// -----------------------------------------------------------------------
// BlockGuard.Protection - DpapiWrapper.cs
// Windows Data Protection API wrapper for file-level encryption at rest.
// -----------------------------------------------------------------------
// SECURITY NOTES:
// - DPAPI LocalMachine scope: any process on the machine CAN decrypt
//   (our ACL layer prevents unauthorized processes from reading the file).
// - DPAPI CurrentUser scope: only the service account can decrypt.
// - Decrypted bytes MUST be zeroed by the caller after use.
// - We add entropy bytes to make the ciphertext unique per file.
// -----------------------------------------------------------------------

using System.Runtime.Versioning;
using System.Security.Cryptography;
using BlockGuard.Core.Configuration;
using BlockGuard.Core.Interfaces;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace BlockGuard.Protection;

/// <summary>
/// Encrypts and decrypts file contents using the Windows DPAPI.
/// Files are encrypted at rest; decryption requires the same machine
/// (LocalMachine scope) or the same user account (CurrentUser scope).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DpapiWrapper : IDpapiWrapper
{
    private readonly ILogger<DpapiWrapper> _logger;
    private readonly DataProtectionScope _scope;

    // Additional entropy to make ciphertext unique even for identical plaintexts.
    // This is NOT a secret — it just prevents rainbow-table attacks on DPAPI blobs.
    private static readonly byte[] Entropy =
        "BlockGuard-v1-FileProtection"u8.ToArray();

    public DpapiWrapper(
        ILogger<DpapiWrapper> logger,
        IOptions<BlockGuardOptions> options)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        var opts = options?.Value ?? throw new ArgumentNullException(nameof(options));

        _scope = opts.DpapiScope?.Equals("CurrentUser", StringComparison.OrdinalIgnoreCase) == true
            ? DataProtectionScope.CurrentUser
            : DataProtectionScope.LocalMachine;

        _logger.LogInformation("DPAPI wrapper initialized with scope: {Scope}", _scope);
    }

    /// <inheritdoc />
    public async Task<string> EncryptFileAsync(
        string filePath, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);

        if (!File.Exists(filePath))
            throw new FileNotFoundException("File to encrypt not found.", filePath);

        byte[] plaintext = [];

        try
        {
            // Read the plaintext file
            plaintext = await File.ReadAllBytesAsync(filePath, cancellationToken);

            if (plaintext.Length == 0)
            {
                _logger.LogWarning("File '{Path}' is empty. Skipping encryption.", filePath);
                return filePath;
            }

            // Encrypt using DPAPI
            var ciphertext = ProtectedData.Protect(plaintext, Entropy, _scope);

            // Write to .enc file
            var encryptedPath = filePath + ".enc";
            await File.WriteAllBytesAsync(encryptedPath, ciphertext, cancellationToken);

            // Securely delete the original plaintext file
            // Overwrite with random data before deletion (defense against forensics)
            await SecureDeleteAsync(filePath, cancellationToken);

            _logger.LogInformation(
                "Encrypted file '{OriginalPath}' -> '{EncryptedPath}' " +
                "({PlaintextSize} bytes -> {CiphertextSize} bytes).",
                filePath, encryptedPath, plaintext.Length, ciphertext.Length);

            return encryptedPath;
        }
        finally
        {
            // CRITICAL: Zero the plaintext buffer to prevent memory leaks
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    /// <inheritdoc />
    public async Task<byte[]> DecryptFileAsync(
        string encryptedFilePath, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(encryptedFilePath);

        if (!File.Exists(encryptedFilePath))
            throw new FileNotFoundException("Encrypted file not found.", encryptedFilePath);

        byte[] ciphertext = [];

        try
        {
            ciphertext = await File.ReadAllBytesAsync(encryptedFilePath, cancellationToken);

            if (ciphertext.Length == 0)
            {
                _logger.LogWarning(
                    "Encrypted file '{Path}' is empty. Returning empty array.",
                    encryptedFilePath);
                return [];
            }

            // Decrypt using DPAPI
            var plaintext = ProtectedData.Unprotect(ciphertext, Entropy, _scope);

            _logger.LogInformation(
                "Decrypted file '{Path}' ({CiphertextSize} bytes -> {PlaintextSize} bytes).",
                encryptedFilePath, ciphertext.Length, plaintext.Length);

            // WARNING: Caller MUST zero this array after use!
            return plaintext;
        }
        catch (CryptographicException ex)
        {
            _logger.LogError(ex,
                "DPAPI decryption failed for '{Path}'. " +
                "This may indicate the file was encrypted on a different machine/user, " +
                "or the DPAPI master key has been rotated.", encryptedFilePath);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ciphertext);
        }
    }

    /// <summary>
    /// Overwrites a file with random data before deleting it.
    /// This provides basic defense against forensic recovery.
    /// NOTE: Not effective on SSDs (due to wear leveling) or NTFS
    /// with journaling. For SSDs, use BitLocker full-disk encryption.
    /// </summary>
    private async Task SecureDeleteAsync(
        string filePath, CancellationToken cancellationToken)
    {
        try
        {
            var fileInfo = new FileInfo(filePath);
            var fileSize = fileInfo.Length;

            // Overwrite with random bytes
            var randomData = new byte[fileSize];
            RandomNumberGenerator.Fill(randomData);

            await using (var stream = new FileStream(
                filePath, FileMode.Open, FileAccess.Write, FileShare.None))
            {
                await stream.WriteAsync(randomData, cancellationToken);
                await stream.FlushAsync(cancellationToken);
            }

            CryptographicOperations.ZeroMemory(randomData);

            // Delete the file
            File.Delete(filePath);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Secure delete failed for '{Path}'. " +
                "The plaintext file may still exist on disk.", filePath);
        }
    }
}
