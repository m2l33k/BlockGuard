// -----------------------------------------------------------------------
// BlockGuard.Core - Interfaces/IDpapiWrapper.cs
// Contract for DPAPI encryption/decryption operations.
// -----------------------------------------------------------------------

namespace BlockGuard.Core.Interfaces;

/// <summary>
/// Wraps the Windows Data Protection API (DPAPI) for encrypting
/// and decrypting protected file contents at rest.
/// </summary>
public interface IDpapiWrapper
{
    /// <summary>
    /// Encrypts the contents of a file using DPAPI and writes the
    /// ciphertext back to the same path (or a .enc extension).
    /// </summary>
    /// <param name="filePath">Path to the plaintext file.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Path to the encrypted file.</returns>
    Task<string> EncryptFileAsync(string filePath, CancellationToken cancellationToken);

    /// <summary>
    /// Decrypts a DPAPI-protected file and returns the plaintext bytes.
    /// The result is stored in a pinned, zeroed buffer that the caller
    /// must explicitly clear after use.
    /// </summary>
    /// <param name="encryptedFilePath">Path to the encrypted file.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Plaintext bytes (caller MUST zero this after use).</returns>
    Task<byte[]> DecryptFileAsync(string encryptedFilePath, CancellationToken cancellationToken);
}
