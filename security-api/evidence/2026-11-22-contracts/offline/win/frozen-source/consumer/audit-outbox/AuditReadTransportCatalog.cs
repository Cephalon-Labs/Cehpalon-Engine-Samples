using System.Collections.ObjectModel;
using System.Text.Json.Nodes;
using Cehpalon.Engine.Transports.GraphQL;
using Cehpalon.Engine.Transports.Http;
using Microsoft.AspNetCore.Routing;

namespace AuditOutbox;

public sealed record AuditReadTransportDescription(string OperationId, string HttpPath, string GraphQLField);

/// <summary>One immutable typed catalog for runtime mapping and offline structural artifacts.</summary>
public sealed class AuditReadTransportCatalog
{
    readonly Exposure[] exposures;
    public IReadOnlyList<AuditReadTransportDescription> Operations { get; }
    AuditReadTransportCatalog(Exposure[] values)
    {
        exposures = values;
        Operations = Array.AsReadOnly(values.Select(x => new AuditReadTransportDescription(x.OperationId, x.Path, x.Field)).ToArray());
    }
    public static AuditReadTransportCatalog Create(AuditReceiptTransportOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var values = new List<Exposure>();
        if ((options.HttpEnabled || options.GraphQLEnabled) && options.ReceiptLookupEnabled)
            values.Add(new Exposure<AuditReceiptLookupRequest, AuditReceiptLookupResponse>(AuditReceiptTransportHost.LookupPath, "trailReceipt", AuditReceiptTransportHost.Binding));
        if ((options.HttpEnabled || options.GraphQLEnabled) && options.ResourceHistoryEnabled)
            values.Add(new Exposure<AuditResourceHistoryRequest, AuditResourceHistoryResponse>(AuditReceiptTransportHost.ResourceHistoryPath, "trailResourceHistory", AuditReceiptTransportHost.ResourceHistoryBinding));
        return new(values.ToArray());
    }
    public int MapHttp(IEndpointRouteBuilder endpoints, Action? mapped = null)
    {
        foreach (var exposure in exposures) { exposure.MapHttp(endpoints); mapped?.Invoke(); }
        return exposures.Length;
    }
    public GraphQLOperationCatalog GraphQL()
    {
        var builder = new GraphQLOperationCatalog.Builder();
        foreach (var exposure in exposures) exposure.AddGraphQL(builder);
        return builder.Build();
    }
    internal IReadOnlyList<Exposure> Exposures => new ReadOnlyCollection<Exposure>(exposures);
    internal abstract record Exposure(string Path, string Field, string OperationId)
    {
        internal abstract void MapHttp(IEndpointRouteBuilder endpoints);
        internal abstract void AddGraphQL(GraphQLOperationCatalog.Builder builder);
        internal abstract JsonNode RequestSchema();
        internal abstract JsonNode ResponseSchema();
    }
    sealed record Exposure<TRequest, TResponse>(string Route, string FieldName, OperationBinding<TRequest, TResponse> Binding)
        : Exposure(Route, FieldName, Binding.OperationId) where TRequest : class where TResponse : class
    {
        internal override void MapHttp(IEndpointRouteBuilder endpoints) => endpoints.MapOperation(Path, Binding);
        internal override void AddGraphQL(GraphQLOperationCatalog.Builder builder) => builder.AddQuery(Field, Binding);
        internal override JsonNode RequestSchema() => OperationHttpAdapter.ExportJsonSchema<TRequest>();
        internal override JsonNode ResponseSchema() => OperationHttpAdapter.ExportJsonSchema<TResponse>();
    }
}
