// -----------------------------------------------------------------------
// BlockGuard.Core - Interfaces/IPolicyEvaluator.cs
// Contract for Layer 2: Policy & Identity Engine.
// -----------------------------------------------------------------------

using BlockGuard.Core.Models;

namespace BlockGuard.Core.Interfaces;

/// <summary>
/// Evaluates whether a given file access event should be permitted.
/// </summary>
public interface IPolicyEvaluator
{
    /// <summary>
    /// Evaluates a file access event against the configured security policy.
    /// </summary>
    /// <param name="accessEvent">The file access event to evaluate.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>An <see cref="AccessDecision"/> with the verdict and reasoning.</returns>
    Task<AccessDecision> EvaluateAsync(FileAccessEvent accessEvent, CancellationToken cancellationToken);
}
