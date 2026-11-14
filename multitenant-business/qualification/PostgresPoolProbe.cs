#:property ManagePackageVersionsCentrally=false
#:property PublishAot=false
#:package Npgsql@10.0.3

using Npgsql;

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

            backend = connection.ProcessID;
            await CheckContext(connection, transaction, null, token);
            await SetContext(connection, transaction, "tenant-a", token);
            await CheckContext(connection, transaction, "tenant-a", token);
            if (commit)
                await transaction.CommitAsync(token);
            else
                await transaction.RollbackAsync(token);

            await using var beforeClose = await connection.BeginTransactionAsync(token);
            await CheckContext(connection, beforeClose, null, token);
            await beforeClose.RollbackAsync(token);
        }

        await using var reused = await source.OpenConnectionAsync(token);
        if (reused.ProcessID != backend)
            throw new InvalidOperationException("The fixture did not reuse the PostgreSQL backend.");

        await using var next = await reused.BeginTransactionAsync(token);
        await CheckContext(reused, next, null, token);
        await SetContext(reused, next, "tenant-b", token);
        await CheckContext(reused, next, "tenant-b", token);
        await next.RollbackAsync(token);
        Console.WriteLine($"{(commit ? "Commit" : "Rollback")}: reused backend {backend}, tenant context isolated.");
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

static async Task CheckContext(NpgsqlConnection connection, NpgsqlTransaction transaction,
    string? expected, CancellationToken token)
{
    using var command = new NpgsqlCommand(
        "SELECT NULLIF(current_setting('cephalon_probe.tenant_id', true), '')", connection, transaction);
    var actual = await command.ExecuteScalarAsync(token);
    if (expected is null ? actual is not DBNull : !Equals(actual, expected))
        throw new InvalidOperationException("Unexpected tenant context in pooled transaction.");
}
