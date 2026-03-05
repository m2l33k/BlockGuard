// -----------------------------------------------------------------------
// BlockGuard.Protection - AuditLogger.cs
// Structured JSON audit logging for all security-relevant events.
// -----------------------------------------------------------------------
// SECURITY NOTES:
// - Audit logging MUST be resilient to failures.
// - Never let an audit write failure crash the protection pipeline.
// - Logs are append-only; rotation is handled by the logging framework.
// - Sensitive data (file hashes, SIDs) are logged; ensure log access is restricted.
// -----------------------------------------------------------------------

using System.Text.Json;
using System.Text.Json.Serialization;
using BlockGuard.Core.Configuration;
using BlockGuard.Core.Interfaces;
using BlockGuard.Core.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace BlockGuard.Protection;

/// <summary>
/// Writes structured audit records to a JSON log file and to the
/// standard logging pipeline (which may include Windows Event Log).
/// </summary>
public sealed class AuditLogger : IAuditLogger
{
    private readonly ILogger<AuditLogger> _logger;
    private readonly string _auditLogPath;
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = false, // Compact JSON for log ingestion
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };

    public AuditLogger(
        ILogger<AuditLogger> logger,
        IOptions<BlockGuardOptions> options)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        var opts = options?.Value ?? throw new ArgumentNullException(nameof(options));

        _auditLogPath = opts.AuditLogPath;

        // Ensure the audit log directory exists
        var dir = Path.GetDirectoryName(_auditLogPath);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
        {
            Directory.CreateDirectory(dir);
        }
    }

    /// <inheritdoc />
    public async Task LogAccessDecisionAsync(
        FileAccessEvent accessEvent, AccessDecision decision)
    {
        try
        {
            var auditRecord = new
            {
                type = "access_decision",
                timestamp = DateTimeOffset.UtcNow,
                eventId = accessEvent.EventId,
                file = accessEvent.FilePath,
                operation = accessEvent.OperationType.ToString(),
                processId = accessEvent.ProcessId,
                threadId = accessEvent.ThreadId,
                verdict = decision.Verdict.ToString(),
                reason = decision.Reason,
                matchedRule = decision.MatchedPolicyRule,
                process = decision.ProcessIdentity != null ? new
                {
                    path = decision.ProcessIdentity.ExecutablePath,
                    hash = decision.ProcessIdentity.FileHash,
                    signed = decision.ProcessIdentity.IsAuthenticodeSigned,
                    signer = decision.ProcessIdentity.SignerSubject,
                    integrityLevel = decision.ProcessIdentity.IntegrityLevel.ToString(),
                    ownerSid = decision.ProcessIdentity.OwnerSid?.Value,
                    parentPid = decision.ProcessIdentity.ParentProcessId
                } : null
            };

            var json = JsonSerializer.Serialize(auditRecord, JsonOptions);
            await WriteLineAsync(json);

            // Also log through the standard pipeline for Event Log / Serilog
            if (decision.Verdict == AccessVerdict.Deny)
            {
                _logger.LogWarning(
                    "[AUDIT] DENIED access to '{File}' by PID {PID} ({Path}). Reason: {Reason}",
                    accessEvent.FilePath, accessEvent.ProcessId,
                    decision.ProcessIdentity?.ExecutablePath ?? "unknown",
                    decision.Reason);
            }
            else
            {
                _logger.LogInformation(
                    "[AUDIT] ALLOWED access to '{File}' by PID {PID} ({Path}). Rule: {Rule}",
                    accessEvent.FilePath, accessEvent.ProcessId,
                    decision.ProcessIdentity?.ExecutablePath ?? "unknown",
                    decision.MatchedPolicyRule);
            }
        }
        catch (Exception ex)
        {
            // NEVER crash the agent due to audit logging failures
            _logger.LogError(ex,
                "Failed to write audit record for event {EventId}. " +
                "Audit data may be incomplete.", accessEvent.EventId);
        }
    }

    /// <inheritdoc />
    public async Task LogOperationalEventAsync(
        string eventType, string message, object? details = null)
    {
        try
        {
            var record = new
            {
                type = "operational",
                timestamp = DateTimeOffset.UtcNow,
                eventType,
                message,
                details
            };

            var json = JsonSerializer.Serialize(record, JsonOptions);
            await WriteLineAsync(json);

            _logger.LogInformation("[AUDIT-OP] {EventType}: {Message}", eventType, message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "Failed to write operational audit record: {EventType}", eventType);
        }
    }

    /// <summary>
    /// Writes a line to the audit log file with thread-safe serialization.
    /// Uses a semaphore to prevent interleaved writes from concurrent events.
    /// </summary>
    private async Task WriteLineAsync(string line)
    {
        await _writeLock.WaitAsync();
        try
        {
            await File.AppendAllTextAsync(
                _auditLogPath,
                line + Environment.NewLine);
        }
        finally
        {
            _writeLock.Release();
        }
    }
}
