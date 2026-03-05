// -----------------------------------------------------------------------
// BlockGuard.Monitoring - EtwFileTraceSession.cs
// Real-time ETW-based file access monitoring using Kernel File provider.
// -----------------------------------------------------------------------
// SECURITY NOTE: ETW kernel sessions require Administrator/SYSTEM privileges.
// The session name must be unique to prevent hijacking by malicious processes.
// -----------------------------------------------------------------------

using System.Collections.Concurrent;
using BlockGuard.Core.Configuration;
using BlockGuard.Core.Interfaces;
using BlockGuard.Core.Models;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace BlockGuard.Monitoring;

/// <summary>
/// Monitors file access in real-time using ETW (Event Tracing for Windows).
/// Subscribes to the kernel file I/O provider and filters events to only
/// emit notifications for protected paths.
/// </summary>
/// <remarks>
/// IMPORTANT: This class runs the ETW processing on a dedicated background thread.
/// Event handlers should offload work to avoid blocking the ETW pump.
/// </remarks>
public sealed class EtwFileTraceSession : IFileAccessMonitor
{
    private readonly ILogger<EtwFileTraceSession> _logger;
    private readonly BlockGuardOptions _options;
    private readonly HashSet<string> _protectedDirectories;
    private readonly HashSet<string> _protectedFiles;

    private TraceEventSession? _session;
    private ETWTraceEventSource? _source;
    private Task? _processingTask;
    private volatile bool _isRunning;

    // Unique session name with GUID to prevent session hijacking
    private static readonly string SessionName =
        $"BlockGuard-FileTrace-{Environment.ProcessId}";

    public event Func<FileAccessEvent, Task>? OnFileAccess;

    public EtwFileTraceSession(
        ILogger<EtwFileTraceSession> logger,
        IOptions<BlockGuardOptions> options)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));

        // Pre-compute normalized protected paths for fast lookup
        _protectedDirectories = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        _protectedFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var path in _options.ProtectedPaths)
        {
            var normalized = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar);
            if (Directory.Exists(normalized))
            {
                _protectedDirectories.Add(normalized);
            }
            else
            {
                _protectedFiles.Add(normalized);
            }
        }
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (_isRunning)
        {
            _logger.LogWarning("ETW session is already running. Ignoring duplicate start request.");
            return Task.CompletedTask;
        }

        _logger.LogInformation(
            "Starting ETW file trace session '{SessionName}' monitoring {FileCount} files and {DirCount} directories.",
            SessionName, _protectedFiles.Count, _protectedDirectories.Count);

        try
        {
            // Dispose any zombie session with the same name (crash recovery)
            try
            {
                using var zombie = new TraceEventSession(SessionName, TraceEventSessionOptions.Attach);
                zombie.Stop();
                _logger.LogWarning("Disposed orphaned ETW session '{SessionName}'.", SessionName);
            }
            catch
            {
                // No zombie session — expected case
            }

            // Create a new real-time ETW session
            _session = new TraceEventSession(SessionName)
            {
                StopOnDispose = true
            };

            // Enable kernel file I/O events
            // We want: FileIOInit (file create/open), DiskFileIO (read/write)
            _session.EnableKernelProvider(
                KernelTraceEventParser.Keywords.FileIOInit |
                KernelTraceEventParser.Keywords.FileIO,
                KernelTraceEventParser.Keywords.None);

            _source = _session.Source;

            // Subscribe to file I/O events
            _source.Kernel.FileIOCreate += OnKernelFileCreate;
            _source.Kernel.FileIORead += OnKernelFileRead;
            _source.Kernel.FileIOWrite += OnKernelFileWrite;
            _source.Kernel.FileIODelete += OnKernelFileDelete;
            _source.Kernel.FileIORename += OnKernelFileRename;

            _isRunning = true;

            // Process ETW events on a dedicated background thread
            // This MUST run on its own thread — ETW.Process() blocks until stopped
            _processingTask = Task.Factory.StartNew(
                () =>
                {
                    try
                    {
                        _source.Process();
                    }
                    catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
                    {
                        _logger.LogCritical(ex, "ETW processing loop crashed unexpectedly.");
                    }
                    finally
                    {
                        _isRunning = false;
                    }
                },
                cancellationToken,
                TaskCreationOptions.LongRunning,
                TaskScheduler.Default);

            _logger.LogInformation("ETW file trace session started successfully.");
        }
        catch (UnauthorizedAccessException ex)
        {
            _logger.LogCritical(ex,
                "Failed to start ETW session — insufficient privileges. " +
                "The agent must run as Administrator or SYSTEM.");
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogCritical(ex, "Failed to start ETW file trace session.");
            throw;
        }

        return Task.CompletedTask;
    }

    public async Task StopAsync()
    {
        if (!_isRunning)
            return;

        _logger.LogInformation("Stopping ETW file trace session '{SessionName}'.", SessionName);
        _isRunning = false;

        try
        {
            _session?.Stop();

            if (_processingTask != null)
            {
                await _processingTask.WaitAsync(TimeSpan.FromSeconds(10));
            }
        }
        catch (TimeoutException)
        {
            _logger.LogWarning("ETW processing task did not stop within timeout. Forcing disposal.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error stopping ETW session.");
        }
    }

    // ----- ETW Event Handlers -----

    private void OnKernelFileCreate(FileIOCreateTraceData data)
    {
        EmitIfProtected(data.FileName, data.ProcessID, data.ThreadID,
            FileOperationType.Create, data.EventName);
    }

    private void OnKernelFileRead(FileIOReadWriteTraceData data)
    {
        EmitIfProtected(data.FileName, data.ProcessID, data.ThreadID,
            FileOperationType.Read, data.EventName);
    }

    private void OnKernelFileWrite(FileIOReadWriteTraceData data)
    {
        EmitIfProtected(data.FileName, data.ProcessID, data.ThreadID,
            FileOperationType.Write, data.EventName);
    }

    private void OnKernelFileDelete(FileIOInfoTraceData data)
    {
        EmitIfProtected(data.FileName, data.ProcessID, data.ThreadID,
            FileOperationType.Delete, data.EventName);
    }

    private void OnKernelFileRename(FileIOInfoTraceData data)
    {
        EmitIfProtected(data.FileName, data.ProcessID, data.ThreadID,
            FileOperationType.Rename, data.EventName);
    }

    /// <summary>
    /// Checks if the accessed file is in a protected path and, if so,
    /// emits a <see cref="FileAccessEvent"/> to subscribers.
    /// </summary>
    private void EmitIfProtected(
        string? filePath, int processId, int threadId,
        FileOperationType opType, string? rawEventName)
    {
        if (string.IsNullOrEmpty(filePath))
            return;

        // Ignore events from our own process to avoid infinite loops
        if (processId == Environment.ProcessId)
            return;

        // Fast path: check if the file is directly in the protected set
        if (!IsProtectedPath(filePath))
            return;

        var accessEvent = new FileAccessEvent
        {
            FilePath = filePath,
            ProcessId = processId,
            ThreadId = threadId,
            OperationType = opType,
            RawEventName = rawEventName
        };

        // Fire-and-forget to avoid blocking the ETW pump thread
        // Errors in handlers are logged but do not crash the monitor
        _ = Task.Run(async () =>
        {
            try
            {
                if (OnFileAccess != null)
                {
                    await OnFileAccess.Invoke(accessEvent);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error in file access event handler for {FilePath} (PID: {ProcessId}).",
                    filePath, processId);
            }
        });
    }

    /// <summary>
    /// Determines if a file path falls under protection.
    /// Uses case-insensitive comparison (NTFS is case-insensitive by default).
    /// </summary>
    private bool IsProtectedPath(string filePath)
    {
        // Direct file match
        if (_protectedFiles.Contains(filePath))
            return true;

        // Directory match — check if the file is under a protected directory
        foreach (var dir in _protectedDirectories)
        {
            if (filePath.StartsWith(dir + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync();

        _source?.Dispose();
        _session?.Dispose();

        _source = null;
        _session = null;

        _logger.LogInformation("ETW file trace session disposed.");
    }
}
