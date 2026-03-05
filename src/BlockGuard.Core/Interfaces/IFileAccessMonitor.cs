// -----------------------------------------------------------------------
// BlockGuard.Core - Interfaces/IFileAccessMonitor.cs
// Contract for Layer 1: Monitoring & Interception.
// -----------------------------------------------------------------------

using BlockGuard.Core.Models;

namespace BlockGuard.Core.Interfaces;

/// <summary>
/// Abstraction for monitoring file system access events.
/// Implementations may use ETW, FileSystemWatcher, or other sources.
/// </summary>
public interface IFileAccessMonitor : IAsyncDisposable
{
    /// <summary>
    /// Starts the monitoring session. Caller should subscribe to
    /// <see cref="OnFileAccess"/> before calling this.
    /// </summary>
    /// <param name="cancellationToken">Token to signal graceful shutdown.</param>
    Task StartAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Stops the monitoring session and releases all resources.
    /// </summary>
    Task StopAsync();

    /// <summary>
    /// Event raised when a file access is detected on a protected path.
    /// Subscribers should handle this asynchronously to avoid blocking the ETW thread.
    /// </summary>
    event Func<FileAccessEvent, Task>? OnFileAccess;
}
