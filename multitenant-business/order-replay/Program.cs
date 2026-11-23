using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using Business.OrderReplay;
using Npgsql;
using RabbitMQ.Client;
using static Business.OrderReplay.ReplayFixture;

if (args.Length != 1 || args[0] is not ("create" or "publish-confirm-only" or "publish" or
    "worker-exit-after-commit" or "worker-replay" or "verify"))
{
    Console.Error.WriteLine("Expected the selected disposable order replay phase.");
    return 2;
}

try
{
    Require(Environment.Version == new Version(11, 0, 0), "Expected .NET runtime 11.0.0.");
    using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(60));
    var token = deadline.Token;
    await using var source = OpenSource();
    var store = new ReplayStore(source);
    await store.VerifyRoleAsync(token);

    switch (args[0])
    {
        case "create":
            await ScopedAsync(Alpha, Place, store.CreateAsync, token);
            Require(await ScopedAsync(Alpha, Inspect, store.InspectAsync, token) == new Ledger(10, "pending", 0, 1, 0, 0),
                "The order and unpublished event did not commit together.");
            Console.WriteLine("Order and outbox committed together.");
            break;

        case "publish-confirm-only":
        case "publish":
            var envelope = await ScopedAsync(Alpha, Publish, store.LoadUnpublishedAsync, token);
            await using (var connection = await ReplayBroker.OpenAsync(token))
            {
                await ReplayBroker.PublishConfirmedAsync(connection, envelope, token);
                if (args[0] == "publish-confirm-only")
                    ExitAtCheckpoint("Publisher confirm observed before outbox mark.", 76);

                await ScopedAsync(Alpha, Publish, (context, ct) => store.MarkPublishedAsync(context, envelope, ct), token);
                Console.WriteLine("Identical event confirmed and outbox marked.");
            }
            break;

        case "worker-exit-after-commit":
            await using (var connection = await ReplayBroker.OpenAsync(token))
            await using (var channel = await connection.CreateChannelAsync(cancellationToken: token))
            {
                var delivery = await ReplayBroker.GetAsync(channel, token);
                Require(!delivery.Redelivered, "Expected the first Worker delivery to be initial.");
                Require(await ScopedAsync(Alpha, Reserve, (context, ct) => store.ApplyAsync(context, delivery.Event, ct), token),
                    "The first Worker delivery did not apply the event.");
                Require(await ScopedAsync(Alpha, Inspect, store.InspectAsync, token) == new Ledger(8, "reserved", 1, 1, 1, 1),
                    "The post-commit ledger did not show precisely one effect.");
                ExitAtCheckpoint("Worker commit acknowledged before delivery ACK.", 77);
            }
            break;

        case "worker-replay":
            await using (var connection = await ReplayBroker.OpenAsync(token))
            await using (var channel = await connection.CreateChannelAsync(cancellationToken: token))
            {
                var redelivered = 0;
                for (var count = 0; count < 2; count++)
                {
                    var delivery = await ReplayBroker.GetAsync(channel, token);
                    Require(!await ScopedAsync(Alpha, Reserve, (context, ct) => store.ApplyAsync(context, delivery.Event, ct), token),
                        "The replay applied another business effect.");
                    if (delivery.Redelivered) redelivered++;
                    await channel.BasicAckAsync(delivery.DeliveryTag, multiple: false, token);
                }
                Require(redelivered == 1, "Expected one redelivery and one initial delivery of the confirmed copy.");
                await ReplayBroker.VerifyEmptyAsync(channel, token);
                Console.WriteLine("Duplicate deliveries acknowledged: 1 redelivered and 1 initial; no second mutation.");
            }
            break;

        case "verify":
            Require(await ScopedAsync(Alpha, Inspect, store.InspectAsync, token) == new Ledger(8, "reserved", 1, 1, 1, 1),
                "The recovered ledger did not show precisely one tenant-A effect.");
            await store.VerifyBoundaryAsync(token);
            Require(await ScopedAsync(Beta, Inspect, store.InspectAsync, token) == new Ledger(20, "pending", 0, 0, 0, 0),
                "The unrelated tenant ledger changed.");
            await store.VerifyBoundaryAsync(token);
            var before = store.OpenAttempts;
            var denied = await DispatchAsync(Alpha, Beta, Inspect, store.InspectAsync, token);
            Require(!denied.IsSuccess && denied.Error.Code == "access.denied" && store.OpenAttempts == before,
                "The cross-tenant fixture call reached PostgreSQL.");
            ReplayBroker.VerifyGuard();
            await using (var connection = await ReplayBroker.OpenAsync(token))
            await using (var channel = await connection.CreateChannelAsync(cancellationToken: token))
                await ReplayBroker.VerifyEmptyAsync(channel, token);
            Console.WriteLine("Final order, stock, inbox and tenant isolation verified; queue empty.");
            break;
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
    Console.Error.WriteLine($"Order replay phase failed ({failure.GetType().Name}).");
    return 1;
}

static NpgsqlDataSource OpenSource()
{
    var client = typeof(NpgsqlDataSource).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
        .InformationalVersion.Split('+')[0];
    Require(client == "10.0.3", "Expected Npgsql 10.0.3.");
    var secret = Environment.GetEnvironmentVariable("CEPHALON_ORDER_REPLAY_POSTGRES");
    if (string.IsNullOrWhiteSpace(secret)) throw new ProofFailure("Expected an owned PostgreSQL connection.");
    var settings = new NpgsqlConnectionStringBuilder(secret);
    Require(settings.Host == "127.0.0.1" && settings.Database == "cephalon_replay_proof" &&
        settings.Username == "cephalon_replay_runtime", "Unexpected PostgreSQL fixture endpoint.");
    settings.Pooling = true;
    settings.MaxPoolSize = 1;
    settings.MinPoolSize = 0;
    settings.NoResetOnClose = false;
    settings.Multiplexing = false;
    settings.Enlist = false;
    return NpgsqlDataSource.Create(settings.ConnectionString);
}

[DoesNotReturn]
static void ExitAtCheckpoint(string receipt, int code)
{
    Console.WriteLine(receipt);
    Console.Out.Flush();
    Environment.Exit(code);
}
