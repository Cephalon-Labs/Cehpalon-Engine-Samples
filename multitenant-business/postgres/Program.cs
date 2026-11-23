using Business.Postgres;
using Cehpalon.Engine.Core;
using Cehpalon.Engine.Identity;
using Cehpalon.Engine.Tenancy;
using Npgsql;
using static OrderFixture;

try
{
    if (args.Length == 0)
        await RunAsync();
    else if (args is ["--crash-stage", var stoppedSignal])
        await OrderCrashChecks.StageAsync(ReadRuntimeSettings(), stoppedSignal);
    else if (args is ["--crash-verify"])
        await OrderCrashChecks.VerifyAsync(ReadRuntimeSettings());
    else
    {
        Console.Error.WriteLine("Run with the disposable PostgreSQL proof runner.");
        return 2;
    }
    return 0;
}
catch (ProofFailure failure)
{
    Console.Error.WriteLine(failure.Message);
    return 1;
}
catch (Exception failure)
{
    Console.Error.WriteLine($"Order proof stopped ({failure.GetType().Name}).");
    return 1;
}

static async Task RunAsync()
{
    using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
    var token = deadline.Token;
    var settings = ReadRuntimeSettings();
    await using var source = NpgsqlDataSource.Create(settings.ConnectionString);
    await CheckRuntimeRoleAsync(source, token);

    var store = new PostgresOrderStore(source);
    var alpha = new TenantId("A");
    var beta = new TenantId("B");
    var correlation = new OperationContext("postgresql-order-fixture");
    TenantOperationContext? retained = null;
    var a = CreateDispatcher(alpha, store, async (context, callToken) =>
    {
        if (retained is not null) return;
        retained = context;
        var before = Work(store);
        await RejectAsync<TenantAccessDeniedException>(() => store.FindAsync(context, 2, callToken).AsTask());
        await RejectAsync<TenantAccessDeniedException>(() => store.CompleteAsync(context, 1, 0, callToken).AsTask());
        Check(Work(store) == before, "Wrong resource or action reached PostgreSQL.");
    });
    var b = CreateDispatcher(beta, store);

    Check(await FindAsync(a, alpha) == new OrderRow(1, "pending", 0), "Tenant A row did not match.");
    await CheckReturnAsync(source, store.LastBackend, token);
    Check(await FindAsync(b, beta) == new OrderRow(1, "review", 0), "Tenant B row did not match.");
    var beforeDenial = Work(store);
    var denied = await a.DispatchAsync<OrderRequest, OrderRow>(
        PostgresOrderStore.ReadOperation, new(beta, 1), correlation, token);
    Check(!denied.IsSuccess && denied.Error?.Code == "access.denied", "Cross-tenant request was not denied.");
    var wrongActionDispatcher = CreateDispatcher(alpha, store, readAction: "orders.inspect");
    var wrongAction = await wrongActionDispatcher.DispatchAsync<OrderRequest, OrderRow>(
        PostgresOrderStore.ReadOperation, new(alpha, 1), correlation, token);
    Check(!wrongAction.IsSuccess && wrongAction.Error.Code == "access.denied", "A different checked action reached the order store.");
    await RejectAsync<TenantAccessDeniedException>(() => store.FindAsync(retained!, 1, token).AsTask());
    using var alreadyCanceled = new CancellationTokenSource();
    alreadyCanceled.Cancel();
    await RejectAsync<OperationCanceledException>(() => a.DispatchAsync<OrderRequest, OrderRow>(
        PostgresOrderStore.ReadOperation, new(alpha, 1), correlation, alreadyCanceled.Token).AsTask());
    Check(Work(store) == beforeDenial, "Denied, stale or canceled scope reached PostgreSQL.");
    Console.WriteLine("Same order ID isolated across tenant dispatches. Six scope controls performed zero database work.");

    var stale = await b.DispatchAsync<CompleteOrderRequest, OrderRow>(
        PostgresOrderStore.UpdateOperation, new(beta, 1, 1), correlation, token);
    Check(!stale.IsSuccess && stale.Error?.Code == "order.not_changed", "Stale revision was not rejected.");
    Check(await FindAsync(b, beta) == new OrderRow(1, "review", 0), "A stale update changed a row.");

    var first = await a.DispatchAsync<CompleteOrderRequest, OrderRow>(
        PostgresOrderStore.UpdateOperation, new(alpha, 1, 0), correlation, token);
    Check(first.IsSuccess && first.Value == new OrderRow(1, "complete", 1), "Commit did not produce the expected row.");
    await CheckReturnAsync(source, store.LastBackend, token);
    Check(await FindAsync(a, alpha) == new OrderRow(1, "complete", 1), "Acknowledged write was missing.");
    Check(await FindAsync(b, beta) == new OrderRow(1, "review", 0), "Tenant A commit affected tenant B.");
    Console.WriteLine("Commit acknowledged. Same backend had no tenant scope after return. Stale revision changed zero rows.");

    using var afterMutation = CancellationTokenSource.CreateLinkedTokenSource(token);
    var aborting = new PostgresOrderStore(source, (_, _) =>
    {
        afterMutation.Cancel();
        return ValueTask.CompletedTask;
    });
    var rollback = CreateDispatcher(beta, aborting);
    var canceled = await RejectAsync<OperationCanceledException>(() =>
        rollback.DispatchAsync<CompleteOrderRequest, OrderRow>(PostgresOrderStore.UpdateOperation,
            new(beta, 1, 0), correlation, afterMutation.Token).AsTask());
    Check(afterMutation.IsCancellationRequested && canceled.CancellationToken == afterMutation.Token &&
        Work(aborting) == (1, 2), "Cancellation was not observed after the attempted write.");
    await CheckReturnAsync(source, aborting.LastBackend, token);
    Check(await FindAsync(b, beta) == new OrderRow(1, "review", 0), "A canceled write became visible.");
    Check(await FindAsync(a, alpha) == new OrderRow(1, "complete", 1), "Rollback affected another tenant.");
    Console.WriteLine("Post-write cancellation rolled back. Same backend had no tenant scope after return.");

    await ConcurrentOrderChecks.RunAsync(settings, alpha, beta, correlation, token);

    async Task<OrderRow> FindAsync(TenantOperationDispatcher dispatcher, TenantId tenant)
    {
        var result = await dispatcher.DispatchAsync<OrderRequest, OrderRow>(
            PostgresOrderStore.ReadOperation, new(tenant, 1), correlation, token);
        Check(result.IsSuccess, "A permitted order read failed.");
        return result.Value!;
    }
}

internal static class OrderFixture
{
    internal static NpgsqlConnectionStringBuilder ReadRuntimeSettings()
    {
        Check(Environment.Version == new Version(11, 0, 0), "Expected .NET runtime 11.0.0.");
        // The fixture owns the role credentials and a one-connection pool on loopback.
        var connectionString = Environment.GetEnvironmentVariable("CEPHALON_ORDERS_RUNTIME")
            ?? throw new ProofFailure("A disposable runtime connection is required.");
        var settings = new NpgsqlConnectionStringBuilder(connectionString);
        Check(settings.Host == "127.0.0.1" && settings.Database == "cephalon_app_proof" &&
            settings.Username == "cephalon_orders_runtime", "Unexpected fixture connection.");
        settings.Pooling = true;
        settings.MaxPoolSize = 1;
        settings.MinPoolSize = 0;
        settings.NoResetOnClose = false;
        settings.Multiplexing = false;
        settings.Enlist = false;
        return settings;
    }

    internal static TenantOperationDispatcher CreateDispatcher(TenantId tenant, PostgresOrderStore store,
        Func<TenantOperationContext, CancellationToken, Task>? beforeRead = null,
        string readAction = PostgresOrderStore.ReadOperation)
    {
        var registry = new TenantOperationRegistryBuilder()
            .Register<OrderRequest, OrderRow>(PostgresOrderStore.ReadOperation, readAction,
                PostgresOrderStore.ResourceKind, request => request,
                request => new(request.Tenant, PostgresOrderStore.ResourceId(request.OrderId)), () => new ReadOrder(store, beforeRead))
            .Register<CompleteOrderRequest, OrderRow>(PostgresOrderStore.UpdateOperation, PostgresOrderStore.UpdateOperation,
                PostgresOrderStore.ResourceKind, request => request,
                request => new(request.Tenant, PostgresOrderStore.ResourceId(request.OrderId)), () => new CompleteOrder(store))
            .Build();
        var authority = new FixtureAuthority(tenant, readAction);
        return new TenantOperationDispatcher(registry,
            new TenantSecurityServices(authority, new(["fixture"], ["fixture"]), authority, authority, TimeSpan.FromSeconds(10), authority));
    }

    internal static async Task CheckRuntimeRoleAsync(NpgsqlDataSource source, CancellationToken token)
    {
        await using var connection = await source.OpenConnectionAsync(token);
        await using var command = new NpgsqlCommand("""
            SELECT current_setting('server_version_num') = '180006'
                AND current_user = session_user AND current_user = 'cephalon_orders_runtime'
                AND role.rolcanlogin AND NOT role.rolsuper AND NOT role.rolbypassrls
                AND NOT pg_has_role(role.oid, orders.relowner, 'MEMBER')
                AND NOT has_schema_privilege(role.rolname, space.oid, 'CREATE')
                AND NOT has_database_privilege(role.rolname, current_database(), 'CREATE')
                AND orders.relrowsecurity AND orders.relforcerowsecurity
            FROM pg_roles AS role
            JOIN pg_class AS orders ON orders.oid = 'cephalon_orders.orders'::regclass
            JOIN pg_namespace AS space ON space.oid = orders.relnamespace
            WHERE role.rolname = current_user
            """, connection);
        Check(await command.ExecuteScalarAsync(token) is true, "Runtime role, schema or PostgreSQL version did not match.");
    }

    internal static async Task CheckReturnAsync(NpgsqlDataSource source, int backend, CancellationToken token)
    {
        await using var connection = await source.OpenConnectionAsync(token);
        Check(connection.ProcessID == backend, "The fixture did not reuse its expected backend.");
        await using var command = new NpgsqlCommand("""
            SELECT NULLIF(current_setting('cephalon_orders.tenant_id', true), '') IS NULL
                AND NOT EXISTS (SELECT 1 FROM cephalon_orders.orders)
            """, connection);
        Check(await command.ExecuteScalarAsync(token) is true, "An unscoped pooled connection saw tenant state or rows.");
    }

    internal static (int Opens, int Commands) Work(PostgresOrderStore store) => (store.OpenAttempts, store.CommandAttempts);

    internal static void Check(bool passed, string message)
    {
        if (!passed) throw new ProofFailure(message);
    }

    internal static async Task<T> RejectAsync<T>(Func<Task> operation) where T : Exception
    {
        try { await operation(); }
        catch (T failure) { return failure; }
        throw new ProofFailure($"Expected rejection ({typeof(T).Name}).");
    }
}

internal sealed class ProofFailure(string message) : Exception(message);
internal sealed record OrderRequest(TenantId Tenant, int OrderId);
internal sealed record CompleteOrderRequest(TenantId Tenant, int OrderId, int ExpectedRevision);

internal sealed class ReadOrder(PostgresOrderStore store, Func<TenantOperationContext, CancellationToken, Task>? beforeRead)
    : ITenantOperationHandler<OrderRequest, OrderRow>
{
    public async ValueTask<OperationResult<OrderRow>> HandleAsync(OrderRequest request, TenantOperationContext context,
        CancellationToken cancellationToken)
    {
        if (beforeRead is not null) await beforeRead(context, cancellationToken);
        var result = await store.FindAsync(context, request.OrderId, cancellationToken);
        return result is not null ? OperationResult<OrderRow>.Success(result)
            : OperationResult<OrderRow>.Failure(new("order.not_found", "No matching order was found."));
    }
}

internal sealed class CompleteOrder(PostgresOrderStore store) : ITenantOperationHandler<CompleteOrderRequest, OrderRow>
{
    public async ValueTask<OperationResult<OrderRow>> HandleAsync(CompleteOrderRequest request, TenantOperationContext context,
        CancellationToken cancellationToken)
    {
        var result = await store.CompleteAsync(context, request.OrderId, request.ExpectedRevision, cancellationToken);
        return result is not null ? OperationResult<OrderRow>.Success(result)
            : OperationResult<OrderRow>.Failure(new("order.not_changed", "No matching order was changed."));
    }
}

internal sealed class FixtureAuthority(TenantId authorized, string readAction) :
    IIdentitySource, ITenantMembershipSource, IResourceScopeSource, ITenantAccessPolicy
{
    private readonly PrincipalId owner = new("fixture", authorized.Value);
    private readonly DateTimeOffset validUntil = DateTimeOffset.UtcNow.AddMinutes(5);

    public ValueTask<IdentitySnapshot?> ResolveAsync(CancellationToken cancellationToken) =>
        ValueTask.FromResult<IdentitySnapshot?>(new(owner, "fixture", validUntil.AddMinutes(-6), validUntil));

    public ValueTask<TenantMembershipSnapshot?> ResolveAsync(IdentitySnapshot identity, TenantId requestedTenant,
        CancellationToken cancellationToken) =>
        ValueTask.FromResult<TenantMembershipSnapshot?>(identity.Principal.Equals(owner) && requestedTenant.Equals(authorized)
            ? new(owner, authorized, isActive: true, validUntil.AddMinutes(-6), validUntil, "fixture-v1") : null);

    public ValueTask<ResourceScopeSnapshot?> ResolveAsync(TenantId requestedTenant, string kind, string resourceId,
        CancellationToken cancellationToken) =>
        ValueTask.FromResult<ResourceScopeSnapshot?>(requestedTenant.Equals(authorized) && kind == PostgresOrderStore.ResourceKind &&
            resourceId is ("1" or "2" or "3" or "4" or "5") ? new(authorized, kind, resourceId, "fixture-v1") : null);

    public ValueTask<bool> IsAllowedAsync(TenantAccessRequest request, CancellationToken cancellationToken) =>
        ValueTask.FromResult(request.Action == readAction || request.Action == PostgresOrderStore.UpdateOperation);
}
