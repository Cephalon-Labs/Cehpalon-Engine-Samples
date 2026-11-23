using System.Globalization;
using System.Reflection;
using System.Text;
using System.Text.Json;
using RabbitMQ.Client;
using RabbitMQ.Client.Events;

const string Queue = "cephalon-restart";
const string Acknowledged = "acknowledged-before-restart";
const string Held = "delivered-unacknowledged";
const string Pending = "confirmed-never-delivered";

Require(args.Length == 2 && args[0] is "seed" or "recover" or "verify-empty",
    "Expected the probe phase and a new receipt directory.");
Require(Environment.Version == new Version(11, 0, 0), "Expected runtime .NET 11.0.0.");
var clientVersion = typeof(ConnectionFactory).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
    .InformationalVersion.Split('+')[0];
Require(clientVersion == "7.2.2", "Expected RabbitMQ.Client 7.2.2.");
var password = Environment.GetEnvironmentVariable("CEPHALON_BROKER_FIXTURE_VALUE");
var port = Environment.GetEnvironmentVariable("CEPHALON_BROKER_FIXTURE_PORT");
Require(!string.IsNullOrWhiteSpace(password) && int.TryParse(port, NumberStyles.None, CultureInfo.InvariantCulture,
    out var candidate) && candidate is > 0 and <= 65535, "Expected an owned loopback fixture.");
using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(120));
var token = deadline.Token;
var factory = new ConnectionFactory
{
    HostName = "127.0.0.1",
    Port = int.Parse(port!, CultureInfo.InvariantCulture),
    UserName = "cephalon_fixture",
    Password = password!,
    AutomaticRecoveryEnabled = false,
};

await using var connection = await factory.CreateConnectionAsync(token);
Require(connection.ServerProperties.TryGetValue("version", out var version) && version is byte[] versionBytes &&
    Encoding.UTF8.GetString(versionBytes) == "4.4.0", "Expected an actual RabbitMQ 4.4.0 connection.");
var shutdown = new TaskCompletionSource<ShutdownEventArgs>(TaskCreationOptions.RunContinuationsAsynchronously);
connection.ConnectionShutdownAsync += (_, reason) =>
{
    shutdown.TrySetResult(reason);
    return Task.CompletedTask;
};

switch (args[0])
{
    case "seed":
        await Seed();
        break;
    case "recover":
        await Recover();
        break;
    default:
        await CheckEmpty();
        WriteReceipt("second-restart", new { ready = 0, emptyRead = true, independentSession = true });
        break;
}

async Task Seed()
{
    await using var publisher = await connection.CreateChannelAsync(
        new CreateChannelOptions(publisherConfirmationsEnabled: true, publisherConfirmationTrackingEnabled: true), token);
    await publisher.QueueDeclareAsync(Queue, durable: true, exclusive: false, autoDelete: false,
        arguments: new Dictionary<string, object?> { ["x-queue-type"] = "quorum", ["x-quorum-initial-group-size"] = 1 },
        cancellationToken: token);
    foreach (var id in new[] { Acknowledged, Held, Pending })
        await publisher.BasicPublishAsync("", Queue, mandatory: true,
            basicProperties: new BasicProperties { MessageId = id, Persistent = true },
            body: Payload(id), cancellationToken: token);
    Require((await publisher.QueueDeclarePassiveAsync(Queue, token)).MessageCount == 3,
        "Expected three confirmed ready messages.");

    await using (var ack = await connection.CreateChannelAsync(cancellationToken: token))
    {
        var prior = await ack.BasicGetAsync(Queue, autoAck: false, cancellationToken: token);
        RequireDelivery(prior, Acknowledged);
        Require(!prior!.Redelivered, "Fresh acknowledged record indicated redelivery.");
        await ack.BasicAckAsync(prior.DeliveryTag, multiple: false, cancellationToken: token);
        await ack.CloseAsync(token);
    }

    await using var hold = await connection.CreateChannelAsync(cancellationToken: token);
    var delivered = await hold.BasicGetAsync(Queue, autoAck: false, cancellationToken: token);
    RequireDelivery(delivered, Held);
    Require(!delivered!.Redelivered, "The held record must be on its first delivery.");
    Require((await publisher.QueueDeclarePassiveAsync(Queue, token)).MessageCount == 1 &&
        hold.IsOpen && connection.IsOpen, "Expected an open channel holding one delivery and one ready record.");
    WriteReceipt("seed-ready", new
    {
        confirmed = 3, payloadsMatched = true, acknowledgedBeforeStop = 1, acknowledgementChannelClosed = true,
        deliveredUnacknowledged = 1, ready = 1, consumerOpen = true,
    });

    var reason = await shutdown.Task.WaitAsync(token);
    Require(reason.Initiator != ShutdownInitiator.Application && !connection.IsOpen,
        "Expected closed connection initiated outside the seed client.");
    WriteReceipt("seed-stopped", new { connectionClosed = true, autoRecovery = false });
}

async Task Recover()
{
    await using var consumer = await connection.CreateChannelAsync(cancellationToken: token);
    Require((await consumer.QueueDeclarePassiveAsync(Queue, token)).MessageCount == 2,
        "The recovered queue must have exactly two ready records.");
    var observed = new Dictionary<string, bool>(StringComparer.Ordinal);
    for (var index = 0; index < 2; index++)
    {
        var received = await consumer.BasicGetAsync(Queue, autoAck: false, cancellationToken: token);
        var id = received?.BasicProperties.MessageId;
        Require(id is Held or Pending, "Received a missing, acknowledged, or unknown record after restart.");
        RequireDelivery(received, id!);
        Require(observed.TryAdd(id!, received!.Redelivered), "The same fixture ID repeated after restart.");
        await consumer.BasicAckAsync(received.DeliveryTag, multiple: false, cancellationToken: token);
    }
    Require(observed[Held] && !observed[Pending], "Redelivery flags did not distinguish held and pending records.");
    await consumer.CloseAsync(token);
    await CheckEmpty();
    WriteReceipt("first-restart", new
    {
        observedReady = 2, replayedUnacknowledged = 1, recoveredPending = 1, acknowledgedBeforeStopRecurred = false,
        payloadsMatched = true, unacknowledgedMarkedRedelivered = true, pendingMarkedRedelivered = false,
        manuallyAcknowledged = 2, readyAfterAcknowledgement = 0, emptyRead = true, independentSession = true,
    });
}

async Task CheckEmpty()
{
    await using var verify = await connection.CreateChannelAsync(cancellationToken: token);
    Require((await verify.QueueDeclarePassiveAsync(Queue, token)).MessageCount == 0,
        "A new channel found ready records.");
    Require(await verify.BasicGetAsync(Queue, autoAck: false, cancellationToken: token) is null,
        "A new channel received an unexpected record.");
    await verify.CloseAsync(token);
}

static byte[] Payload(string id) => Encoding.UTF8.GetBytes("cephalon synthetic record: " + id);

static void RequireDelivery(BasicGetResult? result, string id) =>
    Require(result is not null && result.BasicProperties.MessageId == id && result.BasicProperties.Persistent &&
        result.Body.Span.SequenceEqual(Payload(id)), "Broker delivery did not preserve expected ID, persistence and payload.");

void WriteReceipt(string name, object result)
{
    var path = Path.Combine(args[1], name + ".json");
    var temporary = path + ".tmp";
    using (var output = new FileStream(temporary, FileMode.CreateNew))
        JsonSerializer.Serialize(output, result);
    File.Move(temporary, path);
}

static void Require(bool condition, string message)
{
    if (!condition) throw new InvalidOperationException(message);
}
