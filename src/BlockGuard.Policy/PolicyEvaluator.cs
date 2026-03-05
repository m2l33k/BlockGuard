// -----------------------------------------------------------------------
// BlockGuard.Policy - PolicyEvaluator.cs
// Evaluates whether a process identity matches any authorized policy rule.
// -----------------------------------------------------------------------
// SECURITY NOTE: This evaluator uses AND-logic per rule.
// ALL non-null fields in a rule must match for authorization.
// This prevents partial matches from granting access.
// -----------------------------------------------------------------------

using System.Runtime.Versioning;
using BlockGuard.Core.Configuration;
using BlockGuard.Core.Interfaces;
using BlockGuard.Core.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace BlockGuard.Policy;

/// <summary>
/// Evaluates file access events against the configured security policy.
/// Orchestrates identity validation, caching, and rule matching.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class PolicyEvaluator : IPolicyEvaluator
{
    private readonly ILogger<PolicyEvaluator> _logger;
    private readonly BlockGuardOptions _options;
    private readonly IProcessIdentityValidator _identityValidator;
    private readonly IdentityCache _cache;

    public PolicyEvaluator(
        ILogger<PolicyEvaluator> logger,
        IOptions<BlockGuardOptions> options,
        IProcessIdentityValidator identityValidator,
        IdentityCache cache)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _identityValidator = identityValidator ?? throw new ArgumentNullException(nameof(identityValidator));
        _cache = cache ?? throw new ArgumentNullException(nameof(cache));
    }

    /// <inheritdoc />
    public async Task<AccessDecision> EvaluateAsync(
        FileAccessEvent accessEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(accessEvent);

        // Step 1: Check the identity cache first (fast path)
        var identity = _cache.TryGet(accessEvent.ProcessId);

        if (identity == null)
        {
            // Step 2: Full identity validation (expensive)
            identity = await _identityValidator.ValidateAsync(
                accessEvent.ProcessId, cancellationToken);

            if (identity == null)
            {
                return new AccessDecision
                {
                    EventId = accessEvent.EventId,
                    Verdict = AccessVerdict.Deny,
                    Reason = "Process identity validation failed — process may have " +
                             "exited or access was denied to its token.",
                    ProcessIdentity = null
                };
            }

            // Cache the validated identity
            _cache.Set(accessEvent.ProcessId, identity);
        }

        // Step 3: Match against policy rules
        foreach (var rule in _options.AuthorizedProcesses)
        {
            if (MatchesRule(identity, rule))
            {
                _logger.LogInformation(
                    "ALLOWED: PID {PID} ({Path}) matched rule '{RuleName}' for file '{File}'.",
                    accessEvent.ProcessId, identity.ExecutablePath,
                    rule.RuleName, accessEvent.FilePath);

                return new AccessDecision
                {
                    EventId = accessEvent.EventId,
                    Verdict = AccessVerdict.Allow,
                    Reason = $"Matched authorized process rule: {rule.RuleName}",
                    ProcessIdentity = identity,
                    MatchedPolicyRule = rule.RuleName
                };
            }
        }

        // No rule matched — DENY
        _logger.LogWarning(
            "DENIED: PID {PID} ({Path}) has no matching authorization rule for file '{File}'. " +
            "Hash={Hash}, Signed={Signed}, Integrity={Integrity}",
            accessEvent.ProcessId, identity.ExecutablePath,
            accessEvent.FilePath, identity.FileHash[..12] + "...",
            identity.IsAuthenticodeSigned, identity.IntegrityLevel);

        return new AccessDecision
        {
            EventId = accessEvent.EventId,
            Verdict = AccessVerdict.Deny,
            Reason = "No authorization rule matched this process identity.",
            ProcessIdentity = identity
        };
    }

    /// <summary>
    /// Checks if a process identity matches ALL non-null criteria in a rule.
    /// AND-logic: every specified field must match.
    /// </summary>
    private bool MatchesRule(ProcessIdentity identity, AuthorizedProcessRule rule)
    {
        // Check executable path (case-insensitive, canonicalized)
        if (!string.IsNullOrEmpty(rule.ExecutablePath))
        {
            var normalizedRule = Path.GetFullPath(rule.ExecutablePath);
            if (!string.Equals(identity.ExecutablePath, normalizedRule,
                    StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        // Check file hash (exact match)
        if (!string.IsNullOrEmpty(rule.ExpectedFileHash))
        {
            if (!string.Equals(identity.FileHash, rule.ExpectedFileHash,
                    StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        // Check signature requirement
        if (rule.RequireSignature && !identity.IsAuthenticodeSigned)
        {
            return false;
        }

        // Check signer subject (contains match for flexibility)
        if (!string.IsNullOrEmpty(rule.ExpectedSignerSubject))
        {
            if (identity.SignerSubject == null ||
                !identity.SignerSubject.Contains(
                    rule.ExpectedSignerSubject, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        // Check minimum integrity level
        if (!string.IsNullOrEmpty(rule.MinimumIntegrityLevel))
        {
            if (Enum.TryParse<IntegrityLevel>(rule.MinimumIntegrityLevel, true, out var minLevel))
            {
                if ((int)identity.IntegrityLevel < (int)minLevel)
                {
                    return false;
                }
            }
        }

        return true;
    }
}
