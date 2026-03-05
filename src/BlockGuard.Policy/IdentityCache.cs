// -----------------------------------------------------------------------
// BlockGuard.Policy - IdentityCache.cs
// LRU cache for validated ProcessIdentity objects to avoid repeated
// expensive cryptographic operations (hashing, signature verification).
// -----------------------------------------------------------------------

using System.Collections.Concurrent;
using BlockGuard.Core.Configuration;
using BlockGuard.Core.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace BlockGuard.Policy;

/// <summary>
/// Thread-safe LRU cache for <see cref="ProcessIdentity"/> objects.
/// Entries expire after the configured TTL. Uses a lock-free read path
/// for performance on the ETW hot path.
/// </summary>
public sealed class IdentityCache : IDisposable
{
    private readonly ILogger<IdentityCache> _logger;
    private readonly TimeSpan _ttl;
    private readonly ConcurrentDictionary<int, CacheEntry> _cache = new();
    private readonly Timer _cleanupTimer;
    private readonly int _maxEntries;

    private sealed record CacheEntry(
        ProcessIdentity Identity,
        DateTimeOffset ExpiresAt);

    public IdentityCache(
        ILogger<IdentityCache> logger,
        IOptions<BlockGuardOptions> options)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        var opts = options?.Value ?? throw new ArgumentNullException(nameof(options));

        _ttl = TimeSpan.FromSeconds(opts.IdentityCacheTtlSeconds);
        _maxEntries = 1000; // Reasonable upper bound

        // Periodic cleanup of expired entries (every TTL interval)
        _cleanupTimer = new Timer(
            _ => EvictExpired(),
            null,
            _ttl,
            _ttl);
    }

    /// <summary>
    /// Attempts to retrieve a cached identity for a PID.
    /// Returns null if not found or expired.
    /// </summary>
    public ProcessIdentity? TryGet(int processId)
    {
        if (_cache.TryGetValue(processId, out var entry))
        {
            if (entry.ExpiresAt > DateTimeOffset.UtcNow)
            {
                return entry.Identity;
            }

            // Expired — remove it
            _cache.TryRemove(processId, out _);
        }

        return null;
    }

    /// <summary>
    /// Stores a validated identity in the cache.
    /// If the cache is at capacity, the oldest entries are evicted.
    /// </summary>
    public void Set(int processId, ProcessIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);

        // Enforce capacity limit
        if (_cache.Count >= _maxEntries)
        {
            EvictExpired();

            // If still over capacity, remove oldest 10%
            if (_cache.Count >= _maxEntries)
            {
                var toRemove = _cache
                    .OrderBy(kvp => kvp.Value.ExpiresAt)
                    .Take(_maxEntries / 10)
                    .Select(kvp => kvp.Key)
                    .ToList();

                foreach (var key in toRemove)
                {
                    _cache.TryRemove(key, out _);
                }
            }
        }

        _cache[processId] = new CacheEntry(
            identity, DateTimeOffset.UtcNow + _ttl);
    }

    /// <summary>
    /// Invalidates a specific PID's cached identity.
    /// Call this when a process exits or when the binary changes.
    /// </summary>
    public void Invalidate(int processId)
    {
        _cache.TryRemove(processId, out _);
    }

    /// <summary>
    /// Clears the entire cache. Used during configuration reloads.
    /// </summary>
    public void Clear()
    {
        _cache.Clear();
        _logger.LogInformation("Identity cache cleared.");
    }

    private void EvictExpired()
    {
        var now = DateTimeOffset.UtcNow;
        var expired = _cache
            .Where(kvp => kvp.Value.ExpiresAt <= now)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var key in expired)
        {
            _cache.TryRemove(key, out _);
        }

        if (expired.Count > 0)
        {
            _logger.LogDebug("Evicted {Count} expired identity cache entries.", expired.Count);
        }
    }

    public void Dispose()
    {
        _cleanupTimer.Dispose();
        _cache.Clear();
    }
}
