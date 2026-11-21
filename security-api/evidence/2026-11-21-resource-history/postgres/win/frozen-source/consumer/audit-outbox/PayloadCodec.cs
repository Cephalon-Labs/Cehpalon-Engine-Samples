using System.Text.Json;
using Cehpalon.Engine.Identity;
using Cehpalon.Engine.Tenancy;

namespace AuditOutbox;

// Explicit closed wire shape: no arbitrary object graphs, provider objects, closures or identity sessions.
public static class PayloadCodec
{
    private sealed record Value(string Kind,string? Text,bool? Boolean,decimal? Number);
    private sealed record Field(string Name,Value Before,Value After,bool WasChanged);
    private sealed record Receipt(Guid Id,string Issuer,string Subject,string Scheme,string Tenant,string Operation,string Action,
        string ResourceKind,string ResourceId,string AuthorizationVersion,string Kind,string? BeforeVersion,string? AfterVersion,DateTimeOffset? Reported);
    private sealed record Payload(Receipt Receipt,DateTimeOffset Recorded,string Mode,string CapturedMode,Field[] Fields);
    public static string Encode(TenantChangeAuditRecord record)
    {
        var r=record.Receipt;
        Value V(TenantChangeValue value)=>new(value.Kind.ToString(),value.TextValue,value.BooleanValue,value.DecimalValue);
        var payload=JsonSerializer.Serialize(new Payload(new(r.ReceiptId,r.Principal.Issuer,r.Principal.Subject,r.AuthenticationScheme,r.Tenant.Value,r.OperationId,r.Action,
            r.ResourceKind,r.ResourceId,r.AuthorizationResourceVersion,r.Kind.ToString(),r.BeforeEntityVersion,r.AfterEntityVersion,r.ReportedAtUtc),record.RecordedAtUtc,
            record.Mode.ToString(),record.CapturedMode.ToString(),record.Fields.Select(f=>new Field(f.Name,V(f.Before),V(f.After),f.WasChanged)).ToArray()));
        if(payload.Length>262144)throw new InvalidOperationException("Bounded fixture payload rejected before staging.");
        return payload;
    }
    public static TenantChangeAuditRecord Decode(string payload)
    {
        if(payload.Length>262144)throw new InvalidOperationException("Bounded fixture payload rejected.");
        var data=JsonSerializer.Deserialize<Payload>(payload)??throw new InvalidOperationException("Missing fixture payload.");
        if(data.Fields.Length>64)throw new InvalidOperationException("Too many fixture fields.");
        TenantChangeValue V(Value value)=>Enum.Parse<TenantChangeValueKind>(value.Kind) switch
        {
            TenantChangeValueKind.Missing=>TenantChangeValue.Missing,TenantChangeValueKind.Null=>TenantChangeValue.Null,
            TenantChangeValueKind.Redacted=>TenantChangeValue.Redacted,TenantChangeValueKind.Text=>TenantChangeValue.Text(value.Text!),
            TenantChangeValueKind.Boolean=>TenantChangeValue.Boolean(value.Boolean!.Value),TenantChangeValueKind.Decimal=>TenantChangeValue.Number(value.Number!.Value),
            _=>throw new InvalidOperationException("Unknown fixture value.")
        };
        var r=data.Receipt;
        return new(new(r.Id,new PrincipalId(r.Issuer,r.Subject),r.Scheme,new(r.Tenant),r.Operation,r.Action,r.ResourceKind,r.ResourceId,r.AuthorizationVersion,
            Enum.Parse<TenantChangeKind>(r.Kind),r.BeforeVersion,r.AfterVersion,r.Reported),data.Recorded,Enum.Parse<TenantChangeAuditMode>(data.Mode),
            data.Fields.Select(f=>new TenantChangeField(f.Name,V(f.Before),V(f.After),f.WasChanged)),Enum.Parse<TenantChangeAuditMode>(data.CapturedMode));
    }
}
