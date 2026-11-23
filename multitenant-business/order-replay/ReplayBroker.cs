using System.Reflection;
using System.Text;
using System.Text.Json;
using RabbitMQ.Client;
using static Business.OrderReplay.ReplayFixture;

namespace Business.OrderReplay;

internal sealed record BrokerDelivery(ulong DeliveryTag, bool Redelivered, Envelope Event);

internal static class ReplayBroker
{
    private const string Queue = "cephalon-order-replay";
    private const string Json = "application/json";
    private static readonly string ExpectedMessageId = Expected.EventId.ToString("D");
    private static readonly byte[] ExpectedBody = JsonSerializer.SerializeToUtf8Bytes(Expected);

    internal static async Task<IConnection> OpenAsync(CancellationToken token)
    {
        var client = typeof(ConnectionFactory).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
            .InformationalVersion.Split('+')[0];
        Require(client == "7.2.2", "Expected RabbitMQ.Client 7.2.2.");
        var endpoint = Environment.GetEnvironmentVariable("CEPHALON_ORDER_REPLAY_AMQP");
        if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var uri) || uri.Scheme != "amqp" ||
            uri.Host != "127.0.0.1" || uri.Port is <= 0 or > 65535 ||
            (uri.AbsolutePath != "/" && !string.Equals(uri.AbsolutePath, "/%2F", StringComparison.OrdinalIgnoreCase)) ||
            uri.Query.Length != 0 || uri.Fragment.Length != 0)
            throw new ProofFailure("Expected the owned local AMQP endpoint.");
        var credentials = uri.UserInfo.Split(':', 2);
        Require(credentials is [{ Length: > 0 }, { Length: > 0 }], "Expected explicit fixture AMQP credentials.");
        var factory = new ConnectionFactory
        {
            HostName = "127.0.0.1",
            Port = uri.Port,
            UserName = Uri.UnescapeDataString(credentials[0]),
            Password = Uri.UnescapeDataString(credentials[1]),
            VirtualHost = "/",
            AutomaticRecoveryEnabled = false
        };
        var connection = await factory.CreateConnectionAsync(token);
        if (connection.ServerProperties is { } properties && properties.TryGetValue("version", out var value) &&
            value is byte[] version && Encoding.UTF8.GetString(version) == "4.4.0")
            return connection;
        await connection.DisposeAsync();
        throw new ProofFailure("Expected an actual RabbitMQ 4.4.0 connection.");
    }

    internal static async Task PublishConfirmedAsync(IConnection connection, Envelope envelope, CancellationToken token)
    {
        Require(envelope == Expected, "The published event did not match the fixture contract.");
        await using var channel = await connection.CreateChannelAsync(
            new CreateChannelOptions(publisherConfirmationsEnabled: true, publisherConfirmationTrackingEnabled: true), token);
        await channel.QueueDeclareAsync(Queue, durable: true, exclusive: false, autoDelete: false,
            arguments: new Dictionary<string, object?> { ["x-queue-type"] = "quorum", ["x-quorum-initial-group-size"] = 1 },
            cancellationToken: token);
        await channel.BasicPublishAsync("", Queue, mandatory: true,
            new BasicProperties { ContentType = Json, MessageId = ExpectedMessageId, Persistent = true },
            JsonSerializer.SerializeToUtf8Bytes(envelope), token);
    }

    internal static async Task<BrokerDelivery> GetAsync(IChannel channel, CancellationToken token)
    {
        var delivery = await channel.BasicGetAsync(Queue, autoAck: false, cancellationToken: token);
        if (delivery is null ||
            delivery.Exchange != "" || delivery.RoutingKey != Queue ||
            !Matches(delivery.BasicProperties.MessageId, delivery.BasicProperties.ContentType,
                delivery.BasicProperties.Persistent, delivery.Body.Span))
            throw new ProofFailure("Missing delivery or envelope mismatch; the Worker did not acknowledge it.");
        var envelope = JsonSerializer.Deserialize<Envelope>(delivery.Body.Span)
            ?? throw new ProofFailure("The validated delivery had no event envelope.");
        return new(delivery.DeliveryTag, delivery.Redelivered, envelope);
    }

    internal static async Task VerifyEmptyAsync(IChannel channel, CancellationToken token)
    {
        Require((await channel.QueueDeclarePassiveAsync(Queue, token)).MessageCount == 0,
            "Expected zero ready deliveries.");
        Require(await channel.BasicGetAsync(Queue, autoAck: false, cancellationToken: token) is null,
            "The empty queue returned an unexpected delivery.");
    }

    internal static void VerifyGuard()
    {
        Require(Matches(ExpectedMessageId, Json, true, ExpectedBody), "The fixture envelope guard rejected its valid record.");
        Require(!Matches(null, Json, true, ExpectedBody) && !Matches(ExpectedMessageId, Json, false, ExpectedBody),
            "The envelope guard accepted altered AMQP metadata.");
        foreach (var changed in new[]
        {
            Expected with { Tenant = Beta.Value },
            Expected with { OrderId = Guid.Empty },
            Expected with { SchemaVersion = 2 },
            Expected with { AggregateVersion = 1 },
            Expected with { Quantity = 3 },
            Expected with { EventType = "order.other" }
        })
            Require(!Matches(ExpectedMessageId, Json, true, JsonSerializer.SerializeToUtf8Bytes(changed)),
                "The envelope guard accepted a changed fixture record.");
    }

    private static bool Matches(string? id, string? contentType, bool persistent, ReadOnlySpan<byte> body) =>
        id == ExpectedMessageId && contentType == Json && persistent && body.SequenceEqual(ExpectedBody);
}
