// -----------------------------------------------------------------------
// BlockGuard.Core - Interfaces/IProcessIdentityValidator.cs
// Contract for validating and building a ProcessIdentity from a PID.
// -----------------------------------------------------------------------

using BlockGuard.Core.Models;

namespace BlockGuard.Core.Interfaces;

/// <summary>
/// Validates a running process and constructs its full identity.
/// This is the most security-critical component — all identity checks
/// are centralized here.
/// </summary>
public interface IProcessIdentityValidator
{
    /// <summary>
    /// Fully validates a process by its PID and returns its identity.
    /// </summary>
    /// <param name="processId">The OS process ID to validate.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// A fully populated <see cref="ProcessIdentity"/>, or null if the process
    /// has exited or cannot be accessed (insufficient privileges).
    /// </returns>
    Task<ProcessIdentity?> ValidateAsync(int processId, CancellationToken cancellationToken);
}
