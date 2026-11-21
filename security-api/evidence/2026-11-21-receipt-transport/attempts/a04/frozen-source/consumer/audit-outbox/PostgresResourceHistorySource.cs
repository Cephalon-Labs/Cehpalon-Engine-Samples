using System.Text.RegularExpressions;
using Cehpalon.Engine.Tenancy;
using Npgsql;

namespace AuditOutbox;

// Additive read-only profile. Physical UUID order is tested against canonical Guid-N, not chronology.
public sealed class PostgresResourceHistorySource:ITenantChangeAuditResourceHistorySource
{
    private readonly string connection,schema;private int queries,connections,lastPid;
    public string ApplicationName{get;}="owned-resource-history-"+Guid.NewGuid().ToString("N");
    public int QueryAttempts=>Volatile.Read(ref queries);public int Connections=>Volatile.Read(ref connections);public int LastBackendPid=>Volatile.Read(ref lastPid);
    public PostgresResourceHistorySource(string connectionString,string ownedSchema)
    {if(!Regex.IsMatch(ownedSchema,"\\Aao_[a-f0-9]{32}\\z",RegexOptions.CultureInvariant))throw new ArgumentException("Owned resource history schema required.",nameof(ownedSchema));schema=ownedSchema;connection=new NpgsqlConnectionStringBuilder(connectionString){ApplicationName=ApplicationName}.ConnectionString;}
    public async ValueTask<TenantChangeAuditResourcePage> ReadAsync(TenantId authorizedTenant,TenantChangeAuditResourceQuery query,CancellationToken token)
    {
        token.ThrowIfCancellationRequested();Interlocked.Increment(ref queries);Interlocked.Increment(ref connections);await using var c=new NpgsqlConnection(connection);await c.OpenAsync(token);Volatile.Write(ref lastPid,c.ProcessID);
        await using var command=new NpgsqlCommand($"""
            /* owned-resource-history-query */
            SELECT tenant,receipt,payload FROM {schema}.audit_sink
            WHERE tenant COLLATE "C"=($1::text COLLATE "C")
              AND ($2::uuid IS NULL OR receipt>$2::uuid)
            ORDER BY receipt
            """,c);
        command.Parameters.AddWithValue(authorizedTenant.Value);command.Parameters.AddWithValue(NpgsqlTypes.NpgsqlDbType.Uuid,(object?)query.Continuation?.AfterReceiptId??DBNull.Value);
        var rows=new List<TenantChangeAuditRecord>();await using(var read=await command.ExecuteReaderAsync(token))while(await read.ReadAsync(token))
        {
            var physicalTenant=read.GetString(0);var physicalReceipt=read.GetGuid(1);var record=PayloadCodec.Decode(read.GetString(2));
            if(!StringComparer.Ordinal.Equals(physicalTenant,authorizedTenant.Value)||!StringComparer.Ordinal.Equals(record.Receipt.Tenant.Value,physicalTenant)||record.Receipt.ReceiptId!=physicalReceipt)throw new InvalidOperationException("Resource history physical and decoded row identities differ.");
            // Preserve existing bounded TEXT codec values (including escaped NUL); do not cast payload to json/jsonb.
            if(StringComparer.Ordinal.Equals(record.Receipt.ResourceKind,query.ResourceKind)&&StringComparer.Ordinal.Equals(record.Receipt.ResourceId,query.ResourceId))rows.Add(record);
            if(rows.Count==query.Limit+1)break;
        }
        var selected=rows.Take(query.Limit).ToArray();var next=rows.Count>query.Limit?new TenantChangeAuditResourceCursor(authorizedTenant,query.ResourceKind,query.ResourceId,selected[^1].Receipt.ReceiptId):null;return new(selected,next);
    }
}
