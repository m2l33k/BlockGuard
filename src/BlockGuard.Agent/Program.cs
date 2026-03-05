// -----------------------------------------------------------------------
// BlockGuard.Agent - Program.cs
// Windows Service entry point with DI, Serilog, and service registration.
// -----------------------------------------------------------------------

using BlockGuard.Agent;
using BlockGuard.Core.Configuration;
using BlockGuard.Core.Interfaces;
using BlockGuard.Monitoring;
using BlockGuard.Policy;
using BlockGuard.Protection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Serilog;
using Serilog.Events;

// -----------------------------------------------------------------------
// Bootstrap Serilog for early error capture (before DI is built)
// -----------------------------------------------------------------------
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Debug()
    .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
    .Enrich.FromLogContext()
    .Enrich.WithMachineName()
    .Enrich.WithProcessId()
    .WriteTo.Console(
        outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] [{SourceContext}] {Message:lj}{NewLine}{Exception}")
    .WriteTo.File(
        path: @"C:\ProgramData\BlockGuard\Logs\blockguard-.log",
        rollingInterval: RollingInterval.Day,
        retainedFileCountLimit: 30,
        outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] [{SourceContext}] {Message:lj}{NewLine}{Exception}")
    .CreateLogger();

try
{
    Log.Information("BlockGuard Security Agent initializing...");

    var builder = Host.CreateApplicationBuilder(args);

    // -----------------------------------------------------------------------
    // Configuration binding
    // -----------------------------------------------------------------------
    builder.Services.Configure<BlockGuardOptions>(
        builder.Configuration.GetSection(BlockGuardOptions.SectionName));

    // -----------------------------------------------------------------------
    // Serilog integration
    // -----------------------------------------------------------------------
    builder.Services.AddSerilog();

    // -----------------------------------------------------------------------
    // Layer 1: Monitoring & Interception
    // -----------------------------------------------------------------------
    builder.Services.AddSingleton<IFileAccessMonitor, EtwFileTraceSession>();
    builder.Services.AddSingleton<IAclEnforcer, AclEnforcer>();

    // -----------------------------------------------------------------------
    // Layer 2: Policy & Identity Engine
    // -----------------------------------------------------------------------
    builder.Services.AddSingleton<IProcessIdentityValidator, ProcessIdentityValidator>();
    builder.Services.AddSingleton<IdentityCache>();
    builder.Services.AddSingleton<IPolicyEvaluator, PolicyEvaluator>();

    // -----------------------------------------------------------------------
    // Layer 3: Protection
    // -----------------------------------------------------------------------
    builder.Services.AddSingleton<IDpapiWrapper, DpapiWrapper>();
    builder.Services.AddSingleton<IAuditLogger, AuditLogger>();

    // -----------------------------------------------------------------------
    // Windows Service configuration
    // -----------------------------------------------------------------------
    builder.Services.AddWindowsService(options =>
    {
        options.ServiceName = "BlockGuard";
    });

    // -----------------------------------------------------------------------
    // The main orchestrating service
    // -----------------------------------------------------------------------
    builder.Services.AddHostedService<BlockGuardService>();

    var host = builder.Build();
    await host.RunAsync();
}
catch (Exception ex)
{
    Log.Fatal(ex, "BlockGuard terminated unexpectedly.");
}
finally
{
    Log.Information("BlockGuard shutting down.");
    await Log.CloseAndFlushAsync();
}
