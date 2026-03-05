// -----------------------------------------------------------------------
// BlockGuard.Core - Interfaces/IAuditLogger.cs
// Contract for structured security audit logging.
// -----------------------------------------------------------------------

using BlockGuard.Core.Models;

namespace BlockGuard.Core.Interfaces;

/// <summary>
/// Writes structured audit records for all access attempts.
/// Must be resilient to failures — audit logging should never
/// crash the agent or block the monitoring pipeline.
/// </summary>
public interface IAuditLogger
{
    /// <summary>
    /// Logs an access decision with full context.
    /// </summary>
    /// <param name="accessEvent">The triggering file access event.</param>
    /// <param name="decision">The access decision that was made.</param>
    Task LogAccessDecisionAsync(FileAccessEvent accessEvent, AccessDecision decision);

    /// <summary>
    /// Logs a security-relevant operational event (e.g., agent start/stop,
    /// ACL modification, config change).
    /// </summary>
    /// <param name="eventType">Category of the operational event.</param>
    /// <param name="message">Human-readable description.</param>
    /// <param name="details">Optional structured details (serialized as JSON).</param>
    Task LogOperationalEventAsync(string eventType, string message, object? details = null);
}
