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
    bool SecurityEnabled = true, TimeSpan? ReadTimeout = null)
{
    public bool ReceiptLookupEnabled { get; init; } = true;
    public bool ResourceHistoryEnabled { get; init; }
    public bool ReportReadTimeout { get; init; }
    public AuditReadConcurrencyLimits? ConcurrencyLimits { get; init; }
}
/// <summary>Optional host-local shared dispatch limits; no queue, rate or wire-response bound.</summary>
public sealed record AuditReadConcurrencyLimits(int MaximumConcurrentReads, int MaximumConcurrentReadsPerTenant);
/// <summary>Captured project configuration. Injected authority collaborators remain caller-owned.</summary>
public sealed record AuditReceiptTransportSecurity(string AuthenticationScheme, IdentityTrustPolicy TrustPolicy,
    ITenantMembershipSource Memberships, IResourceScopeSource Resources, ITenantAccessPolicy AccessPolicy,
    TenantChangeAuditPolicy ReadPolicy, TimeSpan? MaximumLeaseLifetime = null);
public sealed record AuditReceiptLookupRequest(string Tenant, Guid ReceiptId);
public sealed record AuditReceiptLookupResponse(string Tenant, AuditReceiptView? Record);
/// <summary>Unsigned selection metadata; construction grants no tenant authority or snapshot guarantee.</summary>
public sealed record AuditResourceHistoryCursor(string Tenant, string ResourceKind, string ResourceId, Guid AfterReceiptId);
public sealed record AuditResourceHistoryRequest(string Tenant, string ResourceKind, string ResourceId,
    int Limit = 50, AuditResourceHistoryCursor? Continuation = null);
public sealed record AuditResourceHistoryResponse(string Tenant, AuditReceiptView[] Entries, AuditResourceHistoryCursor? NextCursor);
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
    public int BudgetFactories;
    public int GraphQLServices, AuthenticationServices, HttpEndpoints, GraphQLEndpoints;
    public int GatewayFactories, HandlerFactories, SourceLookupCalls, ReaderResults;
    public int ResourceGatewayFactories, ResourceHandlerFactories, SourceResourceHistoryCalls, ResourceReaderResults;
    public int ActiveDispatches, CompletedDispatches, RejectedDispatches;
    public CancellationToken LastDispatchToken, LastWorkToken;
    public CancellationToken LastResourceDispatchToken, LastResourceWorkToken;
    public TaskCompletionSource AdmissionClosed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public TaskCompletionSource DrainCompleted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public ConcurrentQueue<string> Events { get; } = new();
    public Action<CancellationToken>? SourceReadStarted;
    public Func<CancellationToken, Task>? AfterProviderRead;
    public Action<CancellationToken>? ResourceSourceReadStarted;
    public Func<CancellationToken, Task>? AfterResourceProviderRead;
    public Func<WebApplication, Task>? StopApplicationAsync;
}

/// <summary>Optional indexed receipt lookup and resource history. The application supplies established JWT and TLS configuration.</summary>
public sealed class AuditReceiptTransportHost : IAsyncDisposable
{
    const string SecurityModule = "receipt.security", SourceModule = "receipt.source", HostModule = "receipt.host";
    const string HttpModule = "receipt.http", GraphModule = "receipt.graphql";
    public const string LookupPath = "/audit/receipts/lookup";
    public const string ResourceHistoryPath = "/audit/resources/history";
    public const string GraphQLPath = "/graphql";
    public static readonly OperationBinding<AuditReceiptLookupRequest, AuditReceiptLookupResponse> Binding = new("trail.lookup", Validate);
    public static readonly OperationBinding<AuditResourceHistoryRequest, AuditResourceHistoryResponse> ResourceHistoryBinding = new("trail.resource-history", ValidateResourceHistory);
    readonly Admission admission;
    readonly TenantOperationConcurrencyBudget? concurrencyBudget;
    ActivationLease? lease;
    public ActivationPlan Plan { get; }
    public AuditReceiptTransportProbe Probe { get; }
    public WebApplication? App { get; private set; }
    public PostgresIndexedAuditStorage? Source { get; private set; }
    public Uri Address => App is null ? throw new InvalidOperationException("The receipt transport host is inactive.") : new(App.Urls.Single());
    public bool IsAdmissionClosed => admission.IsClosed;
    /// <summary>Aggregate protected-dispatch occupancy only; authentication and response mapping/wire are excluded.</summary>
    public TenantOperationConcurrencySnapshot? ConcurrencySnapshot => concurrencyBudget?.GetSnapshot();
    AuditReceiptTransportHost(ActivationPlan plan, AuditReceiptTransportProbe probe, TenantOperationConcurrencyBudget? concurrencyBudget)
    { Plan = plan; Probe = probe; admission = new(probe); this.concurrencyBudget = concurrencyBudget; }

    /// <summary>Pure capability selection; no host, source, budget or authority construction.</summary>
    public static ActivationPlan CompilePlan(AuditReceiptTransportOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var selected = (options.HttpEnabled || options.GraphQLEnabled) && (options.ReceiptLookupEnabled || options.ResourceHistoryEnabled);
        var config = JsonSerializer.Serialize(new { Cehpalon = new { SchemaVersion = 1, Architecture = "Modular", Topology = "SingleProcess", Pattern = "RequestReply",
            Modules = new Dictionary<string, object> {
                [SecurityModule] = new { Enabled = selected && options.SecurityEnabled }, [SourceModule] = new { Enabled = selected },
                [HostModule] = new { Enabled = selected }, [HttpModule] = new { Enabled = selected && options.HttpEnabled }, [GraphModule] = new { Enabled = selected && options.GraphQLEnabled } } } });
        var compiled = CompositionCompiler.Compile(config, [new(SecurityModule, ModuleRole.Support), new(SourceModule, ModuleRole.Support, [SecurityModule]),
            new(HostModule, ModuleRole.Support, [SecurityModule, SourceModule]), new(HttpModule, ModuleRole.EntryPoint, [HostModule]), new(GraphModule, ModuleRole.EntryPoint, [HostModule])]);
        if (!compiled.IsSuccess) throw new ArgumentException("Invalid receipt transport composition.", nameof(options));
        return compiled.Plan!;
    }

    /// <summary>Pure selected bounds; inert profiles intentionally ignore unused values.</summary>
    public static void ValidateSelectedReadSettings(AuditReceiptTransportOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (!(options.HttpEnabled || options.GraphQLEnabled) || !(options.ReceiptLookupEnabled || options.ResourceHistoryEnabled)) return;
        if (options.ConcurrencyLimits is { } limits)
        {
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(limits.MaximumConcurrentReads);
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(limits.MaximumConcurrentReadsPerTenant);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(limits.MaximumConcurrentReadsPerTenant, limits.MaximumConcurrentReads);
        }
        if (options.ReadTimeout is { } bound && (bound <= TimeSpan.Zero || bound > TimeSpan.FromMinutes(1))) throw new ArgumentOutOfRangeException(nameof(options.ReadTimeout));
    }

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
        var selected = (options.HttpEnabled || options.GraphQLEnabled) && (options.ReceiptLookupEnabled || options.ResourceHistoryEnabled);
        var plan = CompilePlan(options);
        // A single immutable host-local budget is validated before any caller callback. Inert/null profiles skip it.
        var budget = selected && options.ConcurrencyLimits is { } limits
            ? new TenantOperationConcurrencyBudget(limits.MaximumConcurrentReads, limits.MaximumConcurrentReadsPerTenant) : null;
        var owner = new AuditReceiptTransportHost(plan, probe ?? new(), budget);
        if (budget is not null) Interlocked.Increment(ref owner.Probe.BudgetFactories);
        if (selected)
        {
            ValidateSelectedReadSettings(options);
            ArgumentNullException.ThrowIfNull(sourceFactory); ArgumentNullException.ThrowIfNull(securityFactory); ArgumentNullException.ThrowIfNull(configureHost);
        }
        var catalog = AuditReadTransportCatalog.Create(options);
        var reportReadTimeout = options.ReportReadTimeout && options.ReadTimeout.HasValue;
        AuditReceiptTransportSecurity? security = null;
        TenantChangeAuditLookupReader? reader = null;
        TenantChangeAuditResourceHistoryReader? resourceReader = null;
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
                    var observed = new ObservedSource(candidate, owner.Probe);
                    if (options.ReceiptLookupEnabled) reader = TenantChangeAuditLookupReader.ActivateWithReadTimeout(security!.ReadPolicy, options.ReadTimeout, () => observed, reportReadTimeout)!;
                    if (options.ResourceHistoryEnabled) resourceReader = TenantChangeAuditResourceHistoryReader.ActivateWithReadTimeout(security!.ReadPolicy, options.ReadTimeout, () => observed, reportReadTimeout)!;
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
                    builder.Services.AddSingleton<ITransportOperationDispatcher>(new Bridge(owner, security!, reader, resourceReader, reportReadTimeout));
                    if (options.GraphQLEnabled)
                    {
                        builder.Services.AddCehpalonGraphQL(catalog.GraphQL());
                    }
                    owner.Probe.GraphQLServices = builder.Services.Count(s => (s.ServiceType.FullName ?? "").StartsWith("HotChocolate.", StringComparison.Ordinal));
                    owner.Probe.AuthenticationServices = builder.Services.Count(s => (s.ServiceType.FullName ?? "").StartsWith("Microsoft.AspNetCore.Authentication.", StringComparison.Ordinal));
                    app = builder.Build(); owner.App = app;
                    var scheme = await app.Services.GetRequiredService<IAuthenticationSchemeProvider>().GetSchemeAsync(security!.AuthenticationScheme).ConfigureAwait(false);
                    if (scheme is null || !typeof(JwtBearerHandler).IsAssignableFrom(scheme.HandlerType)) throw new ArgumentException("Configure the selected established JWT authentication handler.");
                    app.UseAuthentication(); app.UseAuthorization();
                    if (options.HttpEnabled)
                    {
                        catalog.MapHttp(app, () => owner.Probe.HttpEndpoints++);
                    }
                    if (options.GraphQLEnabled) { app.MapCehpalonGraphQL(GraphQLPath); owner.Probe.GraphQLEndpoints = 1; }
                    await app.StartAsync(token).ConfigureAwait(false); owner.Probe.Events.Enqueue("host.started");
                    return new OwnedHost(owner);
                }
                catch (Exception failure)
                {
                    owner.CloseAdmissions();
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
    static TenantChangeAuditResourceQuery ResourceQuery(AuditResourceHistoryRequest request)
    {
        var cursor = request.Continuation;
        return new(request.ResourceKind, request.ResourceId, request.Limit, cursor is null ? null : new(new(cursor.Tenant), cursor.ResourceKind, cursor.ResourceId, cursor.AfterReceiptId));
    }
    static OperationError? ValidateResourceHistory(AuditResourceHistoryRequest request)
    {
        try
        {
            _ = new TenantId(request.Tenant); _ = ResourceQuery(request);
            return request.Continuation is { } cursor && (!StringComparer.Ordinal.Equals(request.Tenant, cursor.Tenant) ||
                !StringComparer.Ordinal.Equals(request.ResourceKind, cursor.ResourceKind) || !StringComparer.Ordinal.Equals(request.ResourceId, cursor.ResourceId)) ? TransportErrors.ValidationFailed() : null;
        }
        catch (ArgumentException) { return TransportErrors.ValidationFailed(); }
    }
    static AuditResourceHistoryCursor? Cursor(TenantChangeAuditResourceCursor? cursor)
        => cursor is null ? null : new(cursor.Tenant.Value, cursor.ResourceKind, cursor.ResourceId, cursor.AfterReceiptId);
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
        CloseAdmissions(); // Both admissions close synchronously before asynchronous shutdown.
        return lease?.DisposeAsync() ?? ValueTask.CompletedTask;
    }
    void CloseAdmissions()
    {
        admission.Close();
        // DrainAsync closes the budget synchronously. Its uncancelled join is awaited after stopping the app.
        _ = concurrencyBudget?.DrainAsync(CancellationToken.None);
    }
    async Task StopAndDrainAsync(WebApplication? app)
    {
        CloseAdmissions(); var failures = new List<Exception>();
        if (app is not null)
            try { if (Probe.StopApplicationAsync is { } stop) await stop(app).ConfigureAwait(false); else await app.StopAsync(CancellationToken.None).ConfigureAwait(false); }
            catch (Exception error) { failures.Add(error); }
        // Kestrel cancellation or a failed stop never transfers ownership of a dispatch.
        await admission.DrainAsync().ConfigureAwait(false);
        if (concurrencyBudget is not null) await concurrencyBudget.DrainAsync(CancellationToken.None).ConfigureAwait(false);
        Probe.Events.Enqueue("host.drained");
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
    sealed class ObservedSource(PostgresIndexedAuditStorage source, AuditReceiptTransportProbe probe) : ITenantChangeAuditLookupSource, ITenantChangeAuditResourceHistorySource
    {
        public async ValueTask<TenantChangeAuditRecord?> FindAsync(TenantId tenant, Guid id, CancellationToken token)
        {
            Interlocked.Increment(ref probe.SourceLookupCalls); probe.LastWorkToken = token; probe.SourceReadStarted?.Invoke(token);
            var record = await source.FindAsync(tenant, id, token).ConfigureAwait(false);
            if (probe.AfterProviderRead is { } after) await after(token).ConfigureAwait(false);
            return record;
        }
        public async ValueTask<TenantChangeAuditResourcePage> ReadAsync(TenantId tenant, TenantChangeAuditResourceQuery query, CancellationToken token)
        {
            Interlocked.Increment(ref probe.SourceResourceHistoryCalls); probe.LastResourceWorkToken = token; probe.ResourceSourceReadStarted?.Invoke(token);
            var page = await source.ReadAsync(tenant, query, token).ConfigureAwait(false);
            if (probe.AfterResourceProviderRead is { } after) await after(token).ConfigureAwait(false);
            return page;
        }
    }
    sealed class Bridge(AuditReceiptTransportHost owner, AuditReceiptTransportSecurity security,
        TenantChangeAuditLookupReader? reader, TenantChangeAuditResourceHistoryReader? resourceReader,
        bool reportReadTimeout) : ITransportOperationDispatcher
    {
        public async ValueTask<OperationResult<TResponse>> DispatchAsync<TRequest, TResponse>(HttpContext http, string id, TRequest request, OperationContext correlation, CancellationToken token)
        {
            using var admitted = owner.admission.Enter();
            var lookup = reader is not null && id == "trail.lookup" && typeof(TRequest) == typeof(AuditReceiptLookupRequest) && typeof(TResponse) == typeof(AuditReceiptLookupResponse);
            var resource = resourceReader is not null && id == "trail.resource-history" && typeof(TRequest) == typeof(AuditResourceHistoryRequest) && typeof(TResponse) == typeof(AuditResourceHistoryResponse);
            if (!lookup && !resource)
                throw new InvalidOperationException("The receipt wire contract does not match its selected operation.");
            if (lookup) owner.Probe.LastDispatchToken = token; else owner.Probe.LastResourceDispatchToken = token;
            var registry = new TenantOperationRegistryBuilder();
            if (reader is not null) registry.Register<LookupRequest, LookupResult>("trail.lookup", "read", "audit-trail", r => r with { }, r => new(new(r.Tenant), "tenant"),
                () => { Interlocked.Increment(ref owner.Probe.HandlerFactories); return new LookupHandler(reader, owner.Probe, reportReadTimeout); });
            if (resourceReader is not null) registry.Register<ResourceHistoryRequest, ResourceHistoryResult>("trail.resource-history", "read", "audit-trail", r => r with { }, r => new(new(r.Tenant), "tenant"),
                () => { Interlocked.Increment(ref owner.Probe.ResourceHandlerFactories); return new ResourceHandler(resourceReader, owner.Probe, reportReadTimeout); });
            var identity = new AspNetCoreJwtIdentitySource(new RequestAccessor(http), security.AuthenticationScheme);
            var services = new TenantSecurityServices(identity, security.TrustPolicy, security.Memberships, security.Resources,
                security.MaximumLeaseLifetime ?? TimeSpan.FromSeconds(30), security.AccessPolicy);
            var tenant = owner.concurrencyBudget is { } budget
                ? TenantOperationDispatcher.WithTenantConcurrencyBudget(registry.Build(), services, budget)
                : new TenantOperationDispatcher(registry.Build(), services);
            var core = new OperationRegistryBuilder();
            Cehpalon.Engine.Generated.OperationRegistrations.RegisterAll(core, new GatewayFactory(tenant, owner.Probe, reader is not null, resourceReader is not null));
            var dispatcher = new OperationDispatcher(core.Build());
            if (lookup)
            {
                var wire = (AuditReceiptLookupRequest)(object)request!;
                var result = await dispatcher.DispatchAsync<LookupRequest, LookupResult>("trail.lookup", new(wire.Tenant, wire.ReceiptId), correlation, token).ConfigureAwait(false);
                if (!result.IsSuccess) return OperationResult<TResponse>.Failure(result.Error);
                return OperationResult<TResponse>.Success((TResponse)(object)new AuditReceiptLookupResponse(result.Value.Tenant, result.Value.Record is null ? null : View(result.Value.Record)));
            }
            else
            {
                var wire = (AuditResourceHistoryRequest)(object)request!;
                var result = await dispatcher.DispatchAsync<ResourceHistoryRequest, ResourceHistoryResult>("trail.resource-history", new(wire.Tenant, ResourceQuery(wire)), correlation, token).ConfigureAwait(false);
                if (!result.IsSuccess) return OperationResult<TResponse>.Failure(result.Error);
                return OperationResult<TResponse>.Success((TResponse)(object)new AuditResourceHistoryResponse(result.Value.Tenant, result.Value.Page.Entries.Select(View).ToArray(), Cursor(result.Value.Page.NextCursor)));
            }
        }
    }
    sealed class RequestAccessor(HttpContext context) : IHttpContextAccessor { public HttpContext? HttpContext { get; set; } = context; }
    sealed class GatewayFactory(TenantOperationDispatcher dispatcher, AuditReceiptTransportProbe probe, bool lookup, bool resource) : IOperationHandlerFactory
    {
        public THandler Create<THandler>() where THandler : class
        {
            if (lookup && typeof(THandler) == typeof(LookupGateway)) { Interlocked.Increment(ref probe.GatewayFactories); return (THandler)(object)new LookupGateway(dispatcher); }
            if (resource && typeof(THandler) == typeof(ResourceHistoryGateway)) { Interlocked.Increment(ref probe.ResourceGatewayFactories); return (THandler)(object)new ResourceHistoryGateway(dispatcher); }
            throw new InvalidOperationException("The audit read gateway is not selected.");
        }
    }
    sealed class LookupHandler(TenantChangeAuditLookupReader reader, AuditReceiptTransportProbe probe, bool reportReadTimeout) : ITenantOperationHandler<LookupRequest, LookupResult>
    {
        public async ValueTask<OperationResult<LookupResult>> HandleAsync(LookupRequest request, TenantOperationContext context, CancellationToken token)
        {
            try
            {
                var record = await reader.FindAsync(context, request.ReceiptId, token).ConfigureAwait(false);
                Interlocked.Increment(ref probe.ReaderResults); return OperationResult<LookupResult>.Success(new(context.Tenant.Value, record));
            }
            catch (TenantChangeAuditReadTimeoutException) when (reportReadTimeout)
            {
                token.ThrowIfCancellationRequested();
                return OperationResult<LookupResult>.Failure(TransportErrors.AuditReadTimeout());
            }
        }
    }
    sealed class ResourceHandler(TenantChangeAuditResourceHistoryReader reader, AuditReceiptTransportProbe probe, bool reportReadTimeout) : ITenantOperationHandler<ResourceHistoryRequest, ResourceHistoryResult>
    {
        public async ValueTask<OperationResult<ResourceHistoryResult>> HandleAsync(ResourceHistoryRequest request, TenantOperationContext context, CancellationToken token)
        {
            try
            {
                var page = await reader.ReadAsync(context, request.Query, token).ConfigureAwait(false);
                Interlocked.Increment(ref probe.ResourceReaderResults); return OperationResult<ResourceHistoryResult>.Success(new(context.Tenant.Value, page));
            }
            catch (TenantChangeAuditReadTimeoutException) when (reportReadTimeout)
            {
                token.ThrowIfCancellationRequested();
                return OperationResult<ResourceHistoryResult>.Failure(TransportErrors.AuditReadTimeout());
            }
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
