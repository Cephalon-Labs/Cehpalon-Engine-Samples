using System.Collections.Concurrent;
using System.Globalization;
using System.Runtime.ExceptionServices;
using System.Text.Json;
using Cehpalon.Engine.Composition;
using Cehpalon.Engine.Core;
using Cehpalon.Engine.Identity;
using Cehpalon.Engine.Identity.AspNetCore;
using Cehpalon.Engine.Tenancy;
using Cehpalon.Engine.Transports.GraphQL;
using Cehpalon.Engine.Transports.Http;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace AuditOutbox;

public sealed record AuditReceiptTransportOptions(bool HttpEnabled = true, bool GraphQLEnabled = true,
    bool SecurityEnabled = true, TimeSpan? ReadTimeout = null);
/// <summary>Captured project configuration. Injected authority collaborators remain caller-owned.</summary>
public sealed record AuditReceiptTransportSecurity(string AuthenticationScheme, IdentityTrustPolicy TrustPolicy,
    ITenantMembershipSource Memberships, IResourceScopeSource Resources, ITenantAccessPolicy AccessPolicy,
    TenantChangeAuditPolicy ReadPolicy, TimeSpan? MaximumLeaseLifetime = null);
public sealed record AuditReceiptLookupRequest(string Tenant, Guid ReceiptId);
public sealed record AuditReceiptLookupResponse(string Tenant, AuditReceiptView? Record);
public sealed record AuditReceiptValueView(string Kind, string? Text, string? Number, bool? Boolean);
public sealed record AuditReceiptFieldView(string Name, AuditReceiptValueView Before, AuditReceiptValueView After, bool WasChanged);
public sealed record AuditReceiptView(string ReceiptId, string RecordedAtUtc, string? ReportedAtUtc,
    string PrincipalIssuer, string PrincipalSubject, string AuthenticationScheme, string Tenant, string OperationId,
    string Action, string ResourceKind, string ResourceId, string AuthorizationResourceVersion,
    string? BeforeEntityVersion, string? AfterEntityVersion, string Kind, string Mode, string CapturedMode, AuditReceiptFieldView[] Fields);

/// <summary>Trusted sample instrumentation only. Callbacks must own their returned work and never log payloads or credentials.</summary>
public sealed class AuditReceiptTransportProbe
{
    public int HostFactories, SecurityFactories, SourceFactories, SourceOpenAttempts, SourceDisposals;
    public int GraphQLServices, AuthenticationServices, HttpEndpoints, GraphQLEndpoints;
    public int GatewayFactories, HandlerFactories, SourceLookupCalls, ReaderResults;
    public int ActiveDispatches, CompletedDispatches, RejectedDispatches;
    public CancellationToken LastDispatchToken, LastWorkToken;
    public TaskCompletionSource AdmissionClosed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public TaskCompletionSource DrainCompleted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public ConcurrentQueue<string> Events { get; } = new();
    public Action<CancellationToken>? SourceReadStarted;
    public Func<TenantChangeAuditRecord?, CancellationToken, Task>? AfterProviderRead;
    public Func<WebApplication, Task>? StopApplicationAsync;
}

/// <summary>Optional indexed receipt lookup only. The application supplies established JWT and TLS configuration.</summary>
public sealed class AuditReceiptTransportHost : IAsyncDisposable
{
    const string SecurityModule = "receipt.security", SourceModule = "receipt.source", HostModule = "receipt.host";
    const string HttpModule = "receipt.http", GraphModule = "receipt.graphql";
    public const string LookupPath = "/audit/receipts/lookup";
    public const string GraphQLPath = "/graphql";
    public static readonly OperationBinding<AuditReceiptLookupRequest, AuditReceiptLookupResponse> Binding = new("trail.lookup", Validate);
    readonly Admission admission;
    ActivationLease? lease;
    public ActivationPlan Plan { get; }
    public AuditReceiptTransportProbe Probe { get; }
    public WebApplication? App { get; private set; }
    public PostgresIndexedAuditStorage? Source { get; private set; }
    public Uri Address => App is null ? throw new InvalidOperationException("The receipt transport host is inactive.") : new(App.Urls.Single());
    public bool IsAdmissionClosed => admission.IsClosed;
    AuditReceiptTransportHost(ActivationPlan plan, AuditReceiptTransportProbe probe)
    { Plan = plan; Probe = probe; admission = new(probe); }

    /// <summary>
    /// ConfigureHost is trusted to establish TLS, JWT cryptographic trust and the default authentication scheme.
    /// A registered handler alone attests none of those settings. The lease owns the delivered storage and web app,
    /// while injected authority collaborators and resources never delivered by a failing factory remain caller-owned.
    /// </summary>
    public static async ValueTask<AuditReceiptTransportHost> ActivateAsync(AuditReceiptTransportOptions options,
        Func<CancellationToken, ValueTask<PostgresIndexedAuditStorage>>? sourceFactory = null,
        Func<AuditReceiptTransportSecurity>? securityFactory = null, Action<WebApplicationBuilder>? configureHost = null,
        AuditReceiptTransportProbe? probe = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        var selected = options.HttpEnabled || options.GraphQLEnabled;
        var config = JsonSerializer.Serialize(new { Cehpalon = new { SchemaVersion = 1, Architecture = "Modular", Topology = "SingleProcess", Pattern = "RequestReply",
            Modules = new Dictionary<string, object> {
                [SecurityModule] = new { Enabled = selected && options.SecurityEnabled }, [SourceModule] = new { Enabled = selected },
                [HostModule] = new { Enabled = selected }, [HttpModule] = new { Enabled = options.HttpEnabled }, [GraphModule] = new { Enabled = options.GraphQLEnabled } } } });
        var compiled = CompositionCompiler.Compile(config, [new(SecurityModule, ModuleRole.Support), new(SourceModule, ModuleRole.Support, [SecurityModule]),
            new(HostModule, ModuleRole.Support, [SecurityModule, SourceModule]), new(HttpModule, ModuleRole.EntryPoint, [HostModule]), new(GraphModule, ModuleRole.EntryPoint, [HostModule])]);
        if (!compiled.IsSuccess) throw new ArgumentException("Invalid receipt transport composition.", nameof(options));
        var owner = new AuditReceiptTransportHost(compiled.Plan!, probe ?? new());
        if (selected)
        {
            if (options.ReadTimeout is { } bound && (bound <= TimeSpan.Zero || bound > TimeSpan.FromMinutes(1))) throw new ArgumentOutOfRangeException(nameof(options.ReadTimeout));
            ArgumentNullException.ThrowIfNull(sourceFactory); ArgumentNullException.ThrowIfNull(securityFactory); ArgumentNullException.ThrowIfNull(configureHost);
        }
        AuditReceiptTransportSecurity? security = null;
        TenantChangeAuditLookupReader? reader = null;
        owner.Probe.Events.Enqueue("plan.validated");
        owner.lease = await PlanActivator.ActivateAsync(owner.Plan, [
            new(SecurityModule, _ =>
            {
                Interlocked.Increment(ref owner.Probe.SecurityFactories); security = securityFactory!() ?? throw new ArgumentException("The receipt security factory returned null.");
                ValidateSecurity(security); owner.Probe.Events.Enqueue("security.validated"); return ValueTask.FromResult<IAsyncDisposable>(new Empty());
            }),
            new(SourceModule, async token =>
            {
                Interlocked.Increment(ref owner.Probe.SourceFactories);
                // Until the factory returns, its partial resources remain factory-owned.
                var candidate = await sourceFactory!(token).ConfigureAwait(false) ?? throw new ArgumentException("The indexed receipt source factory returned null.");
                owner.Source = candidate;
                try
                {
                    token.ThrowIfCancellationRequested();
                    if (candidate.IsDisposed || candidate.IsReady || candidate.InitializationAttempts != 0) throw new ArgumentException("The receipt source must be newly owned and uninitialized.");
                    Interlocked.Increment(ref owner.Probe.SourceOpenAttempts); await candidate.OpenExistingAsync(token).ConfigureAwait(false);
                    reader = TenantChangeAuditLookupReader.ActivateWithBudget(security!.ReadPolicy, options.ReadTimeout, () => new ObservedSource(candidate, owner.Probe))!;
                    owner.Probe.Events.Enqueue("source.ready"); return new OwnedSource(candidate, owner.Probe);
                }
                catch (Exception failure)
                {
                    try { await new OwnedSource(candidate, owner.Probe).DisposeAsync().ConfigureAwait(false); }
                    catch (Exception cleanup) { throw new AggregateException("Receipt source activation and cleanup failed.", failure, cleanup); }
                    ExceptionDispatchInfo.Capture(failure).Throw(); throw;
                }
            }),
            new(HostModule, async token =>
            {
                Interlocked.Increment(ref owner.Probe.HostFactories);
                WebApplication? app = null;
                try
                {
                    var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { Args = [], EnvironmentName = "Production" });
                    builder.Logging.ClearProviders(); configureHost!(builder); builder.Services.AddAuthorization();
                    builder.Services.AddSingleton<ITransportOperationDispatcher>(new Bridge(owner, security!, reader!));
                    if (options.GraphQLEnabled) builder.Services.AddCehpalonGraphQL(new GraphQLOperationCatalog.Builder().AddQuery("trailReceipt", Binding).Build());
                    owner.Probe.GraphQLServices = builder.Services.Count(s => (s.ServiceType.FullName ?? "").StartsWith("HotChocolate.", StringComparison.Ordinal));
                    owner.Probe.AuthenticationServices = builder.Services.Count(s => (s.ServiceType.FullName ?? "").StartsWith("Microsoft.AspNetCore.Authentication.", StringComparison.Ordinal));
                    app = builder.Build(); owner.App = app;
                    var scheme = await app.Services.GetRequiredService<IAuthenticationSchemeProvider>().GetSchemeAsync(security!.AuthenticationScheme).ConfigureAwait(false);
                    if (scheme is null || !typeof(JwtBearerHandler).IsAssignableFrom(scheme.HandlerType)) throw new ArgumentException("Configure the selected established JWT authentication handler.");
                    app.UseAuthentication(); app.UseAuthorization();
                    if (options.HttpEnabled) { app.MapOperation(LookupPath, Binding); owner.Probe.HttpEndpoints = 1; }
                    if (options.GraphQLEnabled) { app.MapCehpalonGraphQL(GraphQLPath); owner.Probe.GraphQLEndpoints = 1; }
                    await app.StartAsync(token).ConfigureAwait(false); owner.Probe.Events.Enqueue("host.started");
                    return new OwnedHost(owner);
                }
                catch (Exception failure)
                {
                    owner.admission.Close();
                    try { await owner.StopAndDrainAsync(app).ConfigureAwait(false); }
                    catch (Exception cleanup) { throw new AggregateException("Receipt host activation and cleanup failed.", failure, cleanup); }
                    ExceptionDispatchInfo.Capture(failure).Throw(); throw;
                }
            }),
            new(HttpModule, _ => ValueTask.FromResult<IAsyncDisposable>(new Empty())),
            new(GraphModule, _ => ValueTask.FromResult<IAsyncDisposable>(new Empty()))
        ], cancellationToken).ConfigureAwait(false);
        return owner;
    }

    static void ValidateSecurity(AuditReceiptTransportSecurity security)
    {
        ArgumentNullException.ThrowIfNull(security.TrustPolicy); ArgumentNullException.ThrowIfNull(security.Memberships);
        ArgumentNullException.ThrowIfNull(security.Resources); ArgumentNullException.ThrowIfNull(security.AccessPolicy); ArgumentNullException.ThrowIfNull(security.ReadPolicy);
        _ = new IdentitySnapshot(new("receipt-config", "validation"), security.AuthenticationScheme, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch.AddSeconds(1));
        var lifetime = security.MaximumLeaseLifetime ?? TimeSpan.FromSeconds(30);
        if (lifetime <= TimeSpan.Zero || lifetime > TimeSpan.FromMinutes(1)) throw new ArgumentOutOfRangeException(nameof(security.MaximumLeaseLifetime));
        if (security.ReadPolicy.Mode == TenantChangeAuditMode.Disabled) throw new ArgumentException("Selected receipt transports require an enabled read policy.");
    }
    static OperationError? Validate(AuditReceiptLookupRequest request)
    {
        try { _ = new TenantId(request.Tenant); return request.ReceiptId == Guid.Empty ? TransportErrors.ValidationFailed() : null; }
        catch (ArgumentException) { return TransportErrors.ValidationFailed(); }
    }
    static AuditReceiptView View(TenantChangeAuditRecord record)
    {
        var receipt = record.Receipt;
        AuditReceiptValueView Value(TenantChangeValue value) => new(value.Kind.ToString(), value.TextValue, value.DecimalValue?.ToString(CultureInfo.InvariantCulture), value.BooleanValue);
        return new(receipt.ReceiptId.ToString("D"), record.RecordedAtUtc.ToString("O", CultureInfo.InvariantCulture), receipt.ReportedAtUtc?.ToString("O", CultureInfo.InvariantCulture),
            receipt.Principal.Issuer, receipt.Principal.Subject, receipt.AuthenticationScheme, receipt.Tenant.Value, receipt.OperationId, receipt.Action, receipt.ResourceKind, receipt.ResourceId,
            receipt.AuthorizationResourceVersion, receipt.BeforeEntityVersion, receipt.AfterEntityVersion, receipt.Kind.ToString(), record.Mode.ToString(), record.CapturedMode.ToString(),
            record.Fields.Select(field => new AuditReceiptFieldView(field.Name, Value(field.Before), Value(field.After), field.WasChanged)).ToArray());
    }

    public ValueTask DisposeAsync()
    {
        admission.Close(); // Synchronous close before any await or caller can race new admission.
        return lease?.DisposeAsync() ?? ValueTask.CompletedTask;
    }
    async Task StopAndDrainAsync(WebApplication? app)
    {
        admission.Close(); var failures = new List<Exception>();
        if (app is not null)
            try { if (Probe.StopApplicationAsync is { } stop) await stop(app).ConfigureAwait(false); else await app.StopAsync(CancellationToken.None).ConfigureAwait(false); }
            catch (Exception error) { failures.Add(error); }
        // Kestrel cancellation or a failed stop never transfers ownership of a dispatch.
        await admission.DrainAsync().ConfigureAwait(false); Probe.Events.Enqueue("host.drained");
        if (app is not null) try { await app.DisposeAsync().ConfigureAwait(false); } catch (Exception error) { failures.Add(error); }
        Probe.Events.Enqueue("host.disposed");
        if (failures.Count == 1) ExceptionDispatchInfo.Capture(failures[0]).Throw();
        if (failures.Count != 0) throw new AggregateException("Receipt host cleanup failed.", failures);
    }
    sealed class Empty : IAsyncDisposable { public ValueTask DisposeAsync() => ValueTask.CompletedTask; }
    sealed class OwnedHost(AuditReceiptTransportHost owner) : IAsyncDisposable
    { public ValueTask DisposeAsync() => new(owner.StopAndDrainAsync(owner.App)); }
    sealed class OwnedSource(PostgresIndexedAuditStorage source, AuditReceiptTransportProbe probe) : IAsyncDisposable
    {
        public async ValueTask DisposeAsync()
        {
            Interlocked.Increment(ref probe.SourceDisposals); probe.Events.Enqueue("source.dispose.started");
            await source.DisposeAsync().ConfigureAwait(false); probe.Events.Enqueue("source.disposed");
        }
    }
    sealed class ObservedSource(PostgresIndexedAuditStorage source, AuditReceiptTransportProbe probe) : ITenantChangeAuditLookupSource
    {
        public async ValueTask<TenantChangeAuditRecord?> FindAsync(TenantId tenant, Guid id, CancellationToken token)
        {
            Interlocked.Increment(ref probe.SourceLookupCalls); probe.LastWorkToken = token; probe.SourceReadStarted?.Invoke(token);
            var record = await source.FindAsync(tenant, id, token).ConfigureAwait(false);
            if (probe.AfterProviderRead is { } after) await after(record, token).ConfigureAwait(false);
            return record;
        }
    }
    sealed class Bridge(AuditReceiptTransportHost owner, AuditReceiptTransportSecurity security, TenantChangeAuditLookupReader reader) : ITransportOperationDispatcher
    {
        public async ValueTask<OperationResult<TResponse>> DispatchAsync<TRequest, TResponse>(HttpContext http, string id, TRequest request, OperationContext correlation, CancellationToken token)
        {
            using var admitted = owner.admission.Enter();
            owner.Probe.LastDispatchToken = token;
            if (id != "trail.lookup" || typeof(TRequest) != typeof(AuditReceiptLookupRequest) || typeof(TResponse) != typeof(AuditReceiptLookupResponse))
                throw new InvalidOperationException("The receipt wire contract does not match its selected operation.");
            var wire = (AuditReceiptLookupRequest)(object)request!;
            var registry = new TenantOperationRegistryBuilder().Register<LookupRequest, LookupResult>("trail.lookup", "read", "audit-trail", r => r with { }, r => new(new(r.Tenant), "tenant"),
                () => { Interlocked.Increment(ref owner.Probe.HandlerFactories); return new LookupHandler(reader, owner.Probe); }).Build();
            var identity = new AspNetCoreJwtIdentitySource(new RequestAccessor(http), security.AuthenticationScheme);
            var services = new TenantSecurityServices(identity, security.TrustPolicy, security.Memberships, security.Resources,
                security.MaximumLeaseLifetime ?? TimeSpan.FromSeconds(30), security.AccessPolicy);
            var tenant = new TenantOperationDispatcher(registry, services); var core = new OperationRegistryBuilder();
            Cehpalon.Engine.Generated.OperationRegistrations.RegisterAll(core, new GatewayFactory(tenant, owner.Probe));
            var result = await new OperationDispatcher(core.Build()).DispatchAsync<LookupRequest, LookupResult>("trail.lookup", new(wire.Tenant, wire.ReceiptId), correlation, token).ConfigureAwait(false);
            if (!result.IsSuccess) return OperationResult<TResponse>.Failure(result.Error);
            var response = new AuditReceiptLookupResponse(result.Value.Tenant, result.Value.Record is null ? null : View(result.Value.Record));
            return OperationResult<TResponse>.Success((TResponse)(object)response);
        }
    }
    sealed class RequestAccessor(HttpContext context) : IHttpContextAccessor { public HttpContext? HttpContext { get; set; } = context; }
    sealed class GatewayFactory(TenantOperationDispatcher dispatcher, AuditReceiptTransportProbe probe) : IOperationHandlerFactory
    {
        public THandler Create<THandler>() where THandler : class
        {
            if (typeof(THandler) != typeof(LookupGateway)) throw new InvalidOperationException("Only the receipt lookup gateway is selected.");
            Interlocked.Increment(ref probe.GatewayFactories); return (THandler)(object)new LookupGateway(dispatcher);
        }
    }
    sealed class LookupHandler(TenantChangeAuditLookupReader reader, AuditReceiptTransportProbe probe) : ITenantOperationHandler<LookupRequest, LookupResult>
    {
        public async ValueTask<OperationResult<LookupResult>> HandleAsync(LookupRequest request, TenantOperationContext context, CancellationToken token)
        {
            var record = await reader.FindAsync(context, request.ReceiptId, token).ConfigureAwait(false);
            Interlocked.Increment(ref probe.ReaderResults); return OperationResult<LookupResult>.Success(new(context.Tenant.Value, record));
        }
    }
    sealed class Admission(AuditReceiptTransportProbe probe)
    {
        readonly object gate = new(); bool closed; int active;
        TaskCompletionSource drained = Completed();
        static TaskCompletionSource Completed() { var value = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously); value.SetResult(); return value; }
        public bool IsClosed { get { lock (gate) return closed; } }
        public IDisposable Enter()
        {
            lock (gate)
            {
                if (closed) { Interlocked.Increment(ref probe.RejectedDispatches); throw new ObjectDisposedException(nameof(AuditReceiptTransportHost)); }
                if (active++ == 0) drained = new(TaskCreationOptions.RunContinuationsAsynchronously);
                Interlocked.Increment(ref probe.ActiveDispatches); return new Exit(this);
            }
        }
        public void Close()
        {
            lock (gate) { closed = true; probe.AdmissionClosed.TrySetResult(); if (active == 0) probe.DrainCompleted.TrySetResult(); }
        }
        public Task DrainAsync() { lock (gate) return drained.Task; }
        void Leave()
        {
            lock (gate)
            {
                Interlocked.Decrement(ref probe.ActiveDispatches); Interlocked.Increment(ref probe.CompletedDispatches);
                if (--active == 0) { drained.TrySetResult(); if (closed) probe.DrainCompleted.TrySetResult(); }
            }
        }
        sealed class Exit(Admission owner) : IDisposable { Admission? current = owner; public void Dispose() => Interlocked.Exchange(ref current, null)?.Leave(); }
    }
}
