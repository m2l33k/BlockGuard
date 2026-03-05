// -----------------------------------------------------------------------
// BlockGuard.Core - Configuration/BlockGuardOptions.cs
// Strongly-typed configuration model for the entire agent.
// -----------------------------------------------------------------------

namespace BlockGuard.Core.Configuration;

/// <summary>
/// Root configuration options, bound from appsettings.json.
/// All paths should be canonical (no relative paths, no symlinks).
/// </summary>
public sealed class BlockGuardOptions
{
    public const string SectionName = "BlockGuard";

    /// <summary>
    /// List of file paths or directory patterns to protect.
    /// Supports glob patterns (e.g., "C:\Secrets\*.key").
    /// </summary>
    public List<string> ProtectedPaths { get; set; } = [];

    /// <summary>
    /// List of authorized process rules. A process must match ALL criteria
    /// in at least one rule to be granted access.
    /// </summary>
    public List<AuthorizedProcessRule> AuthorizedProcesses { get; set; } = [];

    /// <summary>
    /// How long (in seconds) an identity validation remains cached.
    /// Lower = more secure, higher = less CPU overhead.
    /// Default: 30 seconds (reasonable balance).
    /// </summary>
    public int IdentityCacheTtlSeconds { get; set; } = 30;

    /// <summary>
    /// Maximum duration (in seconds) a temporary file handle stays open.
    /// After this, the handle is forcibly closed even if still in use.
    /// Default: 60 seconds.
    /// </summary>
    public int HandleTimeoutSeconds { get; set; } = 60;

    /// <summary>
    /// Path for structured JSON audit logs.
    /// </summary>
    public string AuditLogPath { get; set; } = @"C:\ProgramData\BlockGuard\Logs\audit.json";

    /// <summary>
    /// Whether to use DPAPI to encrypt files at rest (Machine scope).
    /// </summary>
    public bool EnableDpapiEncryption { get; set; } = true;

    /// <summary>
    /// DPAPI scope: "CurrentUser" or "LocalMachine".
    /// LocalMachine allows any process on the same machine to decrypt
    /// (but only if authorized by our agent). CurrentUser is more restrictive.
    /// </summary>
    public string DpapiScope { get; set; } = "LocalMachine";
}

/// <summary>
/// Defines a single authorization rule. A process must match ALL non-null
/// fields to be considered authorized by this rule.
/// </summary>
public sealed class AuthorizedProcessRule
{
    /// <summary>Human-readable name for this rule (for audit logs).</summary>
    public required string RuleName { get; set; }

    /// <summary>
    /// Exact executable path to match (case-insensitive).
    /// Example: "C:\Program Files\MyAI\model.exe"
    /// </summary>
    public string? ExecutablePath { get; set; }

    /// <summary>
    /// SHA-256 hash of the executable file. If set, the process
    /// binary must match this exact hash (tamper detection).
    /// </summary>
    public string? ExpectedFileHash { get; set; }

    /// <summary>
    /// Expected Authenticode signer subject (e.g., "CN=Contoso, O=Contoso Ltd").
    /// If set, the binary must have a valid signature from this signer.
    /// </summary>
    public string? ExpectedSignerSubject { get; set; }

    /// <summary>
    /// Minimum required integrity level. Default: Medium.
    /// </summary>
    public string MinimumIntegrityLevel { get; set; } = "Medium";

    /// <summary>
    /// If true, Authenticode signature is required (not just checked).
    /// </summary>
    public bool RequireSignature { get; set; } = true;
}
