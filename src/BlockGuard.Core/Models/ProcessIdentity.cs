// -----------------------------------------------------------------------
// BlockGuard.Core - Models/ProcessIdentity.cs
// Represents the fully validated identity of a Windows process.
// -----------------------------------------------------------------------

using System.Security.Principal;

namespace BlockGuard.Core.Models;

/// <summary>
/// Encapsulates all security-relevant properties of a process.
/// Built by the Policy layer's ProcessIdentityValidator.
/// </summary>
public sealed record ProcessIdentity
{
    /// <summary>OS Process ID.</summary>
    public required int ProcessId { get; init; }

    /// <summary>Full canonical path to the executable image.</summary>
    public required string ExecutablePath { get; init; }

    /// <summary>SHA-256 hash of the PE file on disk.</summary>
    public required string FileHash { get; init; }

    /// <summary>Whether the executable has a valid Authenticode signature.</summary>
    public required bool IsAuthenticodeSigned { get; init; }

    /// <summary>Subject name from the Authenticode certificate, if signed.</summary>
    public string? SignerSubject { get; init; }

    /// <summary>Security Identifier of the process owner.</summary>
    public SecurityIdentifier? OwnerSid { get; init; }

    /// <summary>Windows integrity level (Untrusted, Low, Medium, High, System).</summary>
    public required IntegrityLevel IntegrityLevel { get; init; }

    /// <summary>Parent process ID (for chain-of-trust validation).</summary>
    public int? ParentProcessId { get; init; }

    /// <summary>Command line arguments (sanitized — never log raw).</summary>
    public string? CommandLine { get; init; }

    /// <summary>Timestamp when this identity was captured.</summary>
    public DateTimeOffset CapturedAt { get; init; } = DateTimeOffset.UtcNow;
}

/// <summary>
/// Windows mandatory integrity levels.
/// Maps to well-known SID values (S-1-16-*).
/// </summary>
public enum IntegrityLevel
{
    Unknown = -1,
    Untrusted = 0,      // S-1-16-0
    Low = 4096,          // S-1-16-4096
    Medium = 8192,       // S-1-16-8192
    MediumPlus = 8448,   // S-1-16-8448
    High = 12288,        // S-1-16-12288
    System = 16384       // S-1-16-16384
}
