// -----------------------------------------------------------------------
// BlockGuard.Core - Models/FileAccessEvent.cs
// Represents a file system access event captured by the monitoring layer.
// -----------------------------------------------------------------------

namespace BlockGuard.Core.Models;

/// <summary>
/// Represents a single file access event captured from ETW or FileSystemWatcher.
/// Immutable record to prevent modification after capture.
/// </summary>
public sealed record FileAccessEvent
{
    /// <summary>Unique event identifier for audit correlation.</summary>
    public Guid EventId { get; init; } = Guid.NewGuid();

    /// <summary>UTC timestamp of when the event was captured.</summary>
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>Full canonical path of the accessed file.</summary>
    public required string FilePath { get; init; }

    /// <summary>Process ID that triggered the file access.</summary>
    public required int ProcessId { get; init; }

    /// <summary>Thread ID within the process (for granular auditing).</summary>
    public int ThreadId { get; init; }

    /// <summary>Type of file operation attempted.</summary>
    public required FileOperationType OperationType { get; init; }

    /// <summary>Raw event name from the ETW provider (for diagnostics).</summary>
    public string? RawEventName { get; init; }
}

/// <summary>
/// Enumerates the file operations we monitor.
/// Mapped from ETW kernel file provider event opcodes.
/// </summary>
public enum FileOperationType
{
    Unknown = 0,
    Create = 1,
    Read = 2,
    Write = 3,
    Delete = 4,
    Rename = 5,
    SetSecurity = 6,
    Close = 7
}
