// -----------------------------------------------------------------------
// BlockGuard.Core - Models/AccessDecision.cs
// Represents the outcome of a policy evaluation.
// -----------------------------------------------------------------------

namespace BlockGuard.Core.Models;

/// <summary>
/// The result of evaluating a file access event against the security policy.
/// Contains the verdict plus audit-relevant metadata.
/// </summary>
public sealed record AccessDecision
{
    /// <summary>Correlates back to the triggering event.</summary>
    public required Guid EventId { get; init; }

    /// <summary>Whether the access is granted or denied.</summary>
    public required AccessVerdict Verdict { get; init; }

    /// <summary>Human-readable reason for the decision (for audit logs).</summary>
    public required string Reason { get; init; }

    /// <summary>The validated process identity (null if validation failed).</summary>
    public ProcessIdentity? ProcessIdentity { get; init; }

    /// <summary>Which policy rule matched (for troubleshooting).</summary>
    public string? MatchedPolicyRule { get; init; }

    /// <summary>UTC timestamp of the decision.</summary>
    public DateTimeOffset DecidedAt { get; init; } = DateTimeOffset.UtcNow;
}

/// <summary>
/// The binary access decision.
/// </summary>
public enum AccessVerdict
{
    /// <summary>Access is denied. The ACL should already enforce this.</summary>
    Deny = 0,

    /// <summary>Access is temporarily granted via a secure handle.</summary>
    Allow = 1
}
