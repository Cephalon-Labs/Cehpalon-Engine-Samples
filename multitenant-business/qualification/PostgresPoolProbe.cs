#:property ManagePackageVersionsCentrally=false
#:property PublishAot=false
#:package Npgsql@10.0.3

using Npgsql;

const string tenantA = "00000000-0000-0000-0000-000000000001";
const string tenantB = "00000000-0000-0000-0000-000000000002";
var runtimePool = args is ["--runtime-pool"];
if (args.Length != 0 && !runtimePool)
{
    Console.Error.WriteLine("Use --runtime-pool only with the disposable runtime-role fixture.");
    return 2;
}

var connectionString = Environment.GetEnvironmentVariable("CEPHALON_PROBE_POSTGRES");
if (string.IsNullOrWhiteSpace(connectionString))
{
    Console.Error.WriteLine("Set CEPHALON_PROBE_POSTGRES to a disposable PostgreSQL 18.6 fixture.");
    return 2;
}

using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
var token = deadline.Token;
try
{
    foreach (var commit in new[] { true, false })
    {
        var settings = new NpgsqlConnectionStringBuilder(connectionString)
        {
            Pooling = true,
            MaxPoolSize = 1,
            MinPoolSize = 0,
            Multiplexing = false,
            Enlist = false,
            NoResetOnClose = false,
        };
        await using var source = NpgsqlDataSource.Create(settings.ConnectionString);
        int backend;
        await using (var connection = await source.OpenConnectionAsync(token))
        {
            await using var transaction = await connection.BeginTransactionAsync(token);
            using var version = new NpgsqlCommand("SHOW server_version_num", connection, transaction);
            if (!Equals(await version.ExecuteScalarAsync(token), "180006"))
                throw new InvalidOperationException("Expected PostgreSQL 18.6.");
            if (runtimePool)
                await CheckRuntimeRole(connection, transaction, token);

            backend = connection.ProcessID;
            await CheckTenantState(connection, transaction, null, runtimePool, token);
            await SetContext(connection, transaction, tenantA, token);
            await CheckTenantState(connection, transaction, tenantA, runtimePool, token);
            if (commit)
                await transaction.CommitAsync(token);
            else
                await transaction.RollbackAsync(token);

            await using var beforeClose = await connection.BeginTransactionAsync(token);
            await CheckTenantState(connection, beforeClose, null, runtimePool, token);
            await beforeClose.RollbackAsync(token);
        }

        await using var reused = await source.OpenConnectionAsync(token);
        if (reused.ProcessID != backend)
            throw new InvalidOperationException("The fixture did not reuse the PostgreSQL backend.");

        await using var next = await reused.BeginTransactionAsync(token);
        await CheckTenantState(reused, next, null, runtimePool, token);
        await SetContext(reused, next, tenantB, token);
        await CheckTenantState(reused, next, tenantB, runtimePool, token);
        await next.RollbackAsync(token);
        var observations = runtimePool ? "runtime role and exact RLS rows verified" : "tenant context isolated";
        Console.WriteLine($"{(commit ? "Commit" : "Rollback")}: reused backend {backend}, {observations}.");
    }
    return 0;
}
catch (Exception error)
{
    Console.Error.WriteLine($"PostgreSQL pool probe failed ({error.GetType().Name}).");
    return 1;
}

static async Task SetContext(NpgsqlConnection connection, NpgsqlTransaction transaction,
    string tenant, CancellationToken token)
{
    using var command = new NpgsqlCommand(
        "SELECT set_config('cephalon_probe.tenant_id', $1, true)", connection, transaction);
    command.Parameters.Add(new NpgsqlParameter<string> { TypedValue = tenant });
    await command.ExecuteScalarAsync(token);
}

static async Task CheckTenantState(NpgsqlConnection connection, NpgsqlTransaction transaction,
    string? expected, bool checkRows, CancellationToken token)
{
    using var command = new NpgsqlCommand(
        "SELECT NULLIF(current_setting('cephalon_probe.tenant_id', true), '')", connection, transaction);
    var actual = await command.ExecuteScalarAsync(token);
    if (expected is null ? actual is not DBNull : !Equals(actual, expected))
        throw new InvalidOperationException("Unexpected tenant context in pooled transaction.");
    if (!checkRows)
        return;

    using var select = new NpgsqlCommand(
        "SELECT tenant_id::text, order_id FROM cephalon_rls_probe.orders", connection, transaction);
    await using var rows = await select.ExecuteReaderAsync(token);
    if (expected is null)
    {
        if (await rows.ReadAsync(token))
            throw new InvalidOperationException("A pooled transaction without tenant context returned a row.");
        return;
    }
    if (!await rows.ReadAsync(token) || rows.GetString(0) != expected || rows.GetInt32(1) != 1 || await rows.ReadAsync(token))
        throw new InvalidOperationException("The scoped transaction did not read exactly its tenant's order.");
}

static async Task CheckRuntimeRole(NpgsqlConnection connection, NpgsqlTransaction transaction, CancellationToken token)
{
    using var command = new NpgsqlCommand("""
        SELECT current_user = session_user AND runtime_role.rolcanlogin
            AND NOT runtime_role.rolsuper AND NOT runtime_role.rolbypassrls
            AND NOT pg_has_role(runtime_role.oid, orders.relowner, 'MEMBER')
            AND orders.relrowsecurity AND orders.relforcerowsecurity
        FROM pg_roles AS runtime_role
        CROSS JOIN pg_class AS orders
        JOIN pg_namespace AS order_schema ON order_schema.oid = orders.relnamespace
        WHERE runtime_role.rolname = current_user AND current_user = 'cephalon_probe_runtime'
            AND order_schema.nspname = 'cephalon_rls_probe' AND orders.relname = 'orders'
        """, connection, transaction);
    if (await command.ExecuteScalarAsync(token) is not true)
        throw new InvalidOperationException("The pool did not authenticate as the restricted runtime role on the RLS fixture.");
}
