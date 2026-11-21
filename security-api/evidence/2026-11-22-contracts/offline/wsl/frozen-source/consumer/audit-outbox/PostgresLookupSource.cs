using System.Text.RegularExpressions;
using Cehpalon.Engine.Tenancy;
using Npgsql;

namespace AuditOutbox;

// Additive consumer adapter. Existing PostgresStore/history/relay SQL stays unchanged.
public sealed class PostgresLookupSource:ITenantChangeAuditLookupSource
{
    private readonly string connection,schema;private int queryAttempts,connections,lastBackendPid;
    public string ApplicationName{get;}="owned-audit-lookup-"+Guid.NewGuid().ToString("N");
    public int QueryAttempts=>Volatile.Read(ref queryAttempts);public int Connections=>Volatile.Read(ref connections);public int LastBackendPid=>Volatile.Read(ref lastBackendPid);
    public PostgresLookupSource(string connectionString,string ownedSchema)
    {
        if(!Regex.IsMatch(ownedSchema,"\\Aao_[a-f0-9]{32}\\z",RegexOptions.CultureInvariant))throw new ArgumentException("Owned lookup schema identifier required.",nameof(ownedSchema));
        schema=ownedSchema;connection=new NpgsqlConnectionStringBuilder(connectionString){ApplicationName=ApplicationName}.ConnectionString;
    }
    public async ValueTask<TenantChangeAuditRecord?> FindAsync(TenantId authorizedTenant,Guid receiptId,CancellationToken token)
    {
        token.ThrowIfCancellationRequested();Interlocked.Increment(ref queryAttempts);Interlocked.Increment(ref connections);
        await using var c=new NpgsqlConnection(connection);await c.OpenAsync(token);Volatile.Write(ref lastBackendPid,c.ProcessID);
        await using var command=new NpgsqlCommand($"/* owned-audit-receipt-lookup */ SELECT payload FROM {schema}.audit_sink WHERE tenant=$1 AND receipt=$2",c);
        command.Parameters.AddWithValue(authorizedTenant.Value);command.Parameters.AddWithValue(receiptId);var value=await command.ExecuteScalarAsync(token);
        return value is null or DBNull?null:PayloadCodec.Decode((string)value);
    }
}
