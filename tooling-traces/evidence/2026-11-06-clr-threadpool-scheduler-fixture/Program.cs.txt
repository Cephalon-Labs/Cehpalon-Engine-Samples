using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;

if (!OperatingSystem.IsLinux() || RuntimeInformation.ProcessArchitecture != Architecture.X64 || args.Length != 0)
{
    Console.Error.WriteLine("The ThreadPool fixture expects Linux x64 and no arguments.");
    return 2;
}

Native.Alarm(30);
try
{
    using var actor = new Actor();
    actor.Run();
    return 0;
}
catch (Exception error)
{
    Console.WriteLine(JsonSerializer.Serialize(new { kind = "actor_error", message = error.Message }));
    return 1;
}

sealed class Actor : IDisposable
{
    private const int LeaderCpu = 0;
    private const int WorkerCpu = 1;
    private const int Rounds = 64;
    private const ulong ExpectedChecksum = 0x4fcd3a1dd438d325;

    private readonly PipePair _wake = new();
    private readonly PipePair _ack = new();
    private readonly ManualResetEventSlim _workDone = new();
    private readonly int _pid = Environment.ProcessId;
    private readonly int _leaderTid = Native.GetTid();
    private int _workerTid;
    private ulong _checksum;
    private Exception? _workerError;
    private long _workBeginNs;
    private long _workBeginTicks;
    private long _workEndNs;
    private long _workEndTicks;
    private bool _queued;
    private bool _completed;

    public void Run()
    {
        if (_leaderTid != _pid)
            throw new InvalidOperationException("Actor is not running on the process leader.");
        Native.Pin(LeaderCpu);
        var runtimeVersion = JsonSerializer.Serialize(RuntimeInformation.FrameworkDescription);
        var count = ThreadPool.ThreadCount;
        Send(FormattableString.Invariant($"{{\"kind\":\"ready\",\"fixture_version\":1,\"pid\":{_pid},\"main_tid\":{_leaderTid},\"main_cpu\":{LeaderCpu},\"worker_cpu\":{WorkerCpu},\"runtime_version\":{runtimeVersion},\"stopwatch_frequency\":{Stopwatch.Frequency},\"threadpool_count\":{count},\"mono_ns\":{Native.MonotonicNs()}}}"));

        for (var i = 0; i < 8; i++)
        {
            switch (ReadCommand())
            {
                case "marker" when !_queued:
                    Marker();
                    break;
                case "run" when !_queued:
                    QueueWorker();
                    break;
                case "wake" when _queued && !_completed:
                    PingWorker();
                    break;
                case "finish" when !_queued || _completed:
                    var complete = _completed ? "true" : "false";
                    Send(FormattableString.Invariant($"{{\"kind\":\"finished\",\"pid\":{_pid},\"main_tid\":{_leaderTid},\"mono_ns\":{Native.MonotonicNs()},\"worker_completed\":{complete}}}"));
                    return;
                default:
                    throw new InvalidOperationException("Unexpected actor command or phase.");
            }
        }
        throw new InvalidOperationException("Actor command limit reached.");
    }

    private void Marker()
    {
        Native.RequireCpu(LeaderCpu);
        var before = Native.MonotonicNs();
        var tid = Native.GetTid();
        var after = Native.MonotonicNs();
        if (tid != _leaderTid)
            throw new InvalidOperationException("Marker ran off the held leader.");
        Send(FormattableString.Invariant($"{{\"kind\":\"marker\",\"local_tid\":{tid},\"cpu\":{LeaderCpu},\"mono_before_ns\":{before},\"mono_after_ns\":{after}}}"));
    }

    private void QueueWorker()
    {
        if (ThreadPool.ThreadCount != 0)
            throw new InvalidOperationException("ThreadPool already has workers before release.");
        _queued = true;
        _workBeginTicks = Stopwatch.GetTimestamp();
        _workBeginNs = Native.MonotonicNs();
        if (!ThreadPool.UnsafeQueueUserWorkItem(static actor => actor.Worker(), this, preferLocal: false))
            throw new InvalidOperationException("ThreadPool rejected the fixture callback.");
    }

    private void Worker()
    {
        var parked = false;
        try
        {
            Native.Pin(WorkerCpu);
            _workerTid = Native.GetTid();
            var thread = Thread.CurrentThread;
            if (!thread.IsThreadPoolThread || _workerTid == _leaderTid)
                throw new InvalidOperationException("Callback did not run on a distinct CLR ThreadPool worker.");
            Send(FormattableString.Invariant($"{{\"kind\":\"park\",\"worker_tid\":{_workerTid},\"worker_cpu\":{WorkerCpu},\"park_read_fd\":{_wake.ReadFd},\"mono_ns\":{Native.MonotonicNs()},\"work_begin_ns\":{_workBeginNs},\"work_begin_ticks\":{_workBeginTicks},\"is_thread_pool_thread\":true,\"managed_thread_id\":{thread.ManagedThreadId}}}"));
            parked = true;

            ulong checksum = 14695981039346656037;
            for (var round = 0; round < Rounds; round++)
            {
                var marker = Native.ReadByte(_wake.ReadFd);
                if (marker != round + 1)
                    throw new InvalidOperationException("Worker received the wrong round marker.");
                for (var offset = 1; offset <= 64; offset++)
                    checksum = unchecked((checksum ^ (ulong)(round * 64 + offset)) * 1099511628211);
                Native.WriteByte(_ack.WriteFd, marker);
            }
            Native.RequireCpu(WorkerCpu);
            _checksum = checksum;
            _workEndNs = Native.MonotonicNs();
            _workEndTicks = Stopwatch.GetTimestamp();
        }
        catch (Exception error)
        {
            _workerError = error;
            if (!parked)
                Console.WriteLine(JsonSerializer.Serialize(new { kind = "actor_error", message = error.Message }));
        }
        finally
        {
            _workDone.Set();
        }
    }

    private void PingWorker()
    {
        Native.RequireCpu(LeaderCpu);
        var beginCpu = Native.ProcessCpuNs();
        var beginTicks = Stopwatch.GetTimestamp();
        var beginNs = Native.MonotonicNs();
        for (var round = 1; round <= Rounds; round++)
        {
            Native.WriteByte(_wake.WriteFd, (byte)round);
            Native.WaitReadable(_ack.ReadFd);
            if (Native.ReadByte(_ack.ReadFd) != round)
                throw new InvalidOperationException("Leader received the wrong round acknowledgement.");
        }
        var endNs = Native.MonotonicNs();
        var endTicks = Stopwatch.GetTimestamp();
        var endCpu = Native.ProcessCpuNs();
        Native.RequireCpu(LeaderCpu);
        if (!_workDone.Wait(TimeSpan.FromSeconds(2)))
            throw new TimeoutException("Worker did not complete.");
        if (_workerError is not null)
            throw new InvalidOperationException("Worker failed.", _workerError);
        if (_checksum != ExpectedChecksum)
            throw new InvalidOperationException("Fixed worker checksum did not match.");
        _completed = true;
        Send(FormattableString.Invariant($"{{\"kind\":\"completed\",\"worker_tid\":{_workerTid},\"main_cpu\":{LeaderCpu},\"worker_cpu\":{WorkerCpu},\"rounds\":{Rounds},\"checksum\":\"{_checksum:x16}\",\"work_begin_ns\":{_workBeginNs},\"work_end_ns\":{_workEndNs},\"ping_begin_ns\":{beginNs},\"ping_end_ns\":{endNs},\"work_begin_ticks\":{_workBeginTicks},\"work_end_ticks\":{_workEndTicks},\"ping_begin_ticks\":{beginTicks},\"ping_end_ticks\":{endTicks},\"ping_begin_process_cpu_ns\":{beginCpu},\"ping_end_process_cpu_ns\":{endCpu}}}"));
    }

    private static string ReadCommand()
    {
        var line = Console.ReadLine();
        if (line is null || line.Length > 64)
            throw new InvalidOperationException("Actor command is absent or oversized.");
        using var document = JsonDocument.Parse(line);
        var properties = document.RootElement.EnumerateObject();
        if (!properties.MoveNext() || !properties.Current.NameEquals("command"))
            throw new InvalidOperationException("Actor command is missing.");
        var command = properties.Current.Value.GetString();
        if (properties.MoveNext() || command is null)
            throw new InvalidOperationException("Actor command is ambiguous.");
        return command;
    }

    private static void Send(string frame)
    {
        Console.WriteLine(frame);
        Console.Out.Flush();
    }

    public void Dispose()
    {
        _ack.Dispose();
        _wake.Dispose();
        if (!_queued || _completed)
            _workDone.Dispose();
    }
}

sealed class PipePair : IDisposable
{
    public PipePair()
    {
        var fds = new int[2];
        Native.Check(Native.Pipe2(fds, 0x80000), "pipe2");
        ReadFd = fds[0];
        WriteFd = fds[1];
    }

    public int ReadFd { get; }
    public int WriteFd { get; }

    public void Dispose()
    {
        var readClose = Native.Close(ReadFd);
        var writeClose = Native.Close(WriteFd);
        if (readClose != 0 || writeClose != 0)
            throw new InvalidOperationException("Actor did not close an owned pipe.");
    }
}

static class Native
{
    private const int Interrupted = 4;
    private const short PollIn = 1;

    [DllImport("libc", EntryPoint = "syscall", SetLastError = true)]
    private static extern long Syscall(long number);

    [DllImport("libc", EntryPoint = "syscall", SetLastError = true)]
    private static extern long SyscallRead(long number, int fd, out byte value, nuint count);

    [DllImport("libc", EntryPoint = "write", SetLastError = true)]
    private static extern nint Write(int fd, ref byte value, nuint count);

    [DllImport("libc", EntryPoint = "sched_setaffinity", SetLastError = true)]
    private static extern int SetAffinity(int pid, nuint size, ref ulong mask);

    [DllImport("libc", EntryPoint = "sched_getcpu", SetLastError = true)]
    private static extern int GetCpu();

    [DllImport("libc", EntryPoint = "clock_gettime", SetLastError = true)]
    private static extern int ClockGetTime(int clock, out Timespec time);

    [DllImport("libc", EntryPoint = "poll", SetLastError = true)]
    private static extern int Poll(ref PollFd fd, nuint count, int timeoutMs);

    [DllImport("libc", EntryPoint = "pipe2", SetLastError = true)]
    internal static extern int Pipe2([Out] int[] fds, int flags);

    [DllImport("libc", EntryPoint = "close", SetLastError = true)]
    internal static extern int Close(int fd);

    [DllImport("libc", EntryPoint = "alarm")]
    internal static extern uint Alarm(uint seconds);

    [StructLayout(LayoutKind.Sequential)]
    private struct Timespec
    {
        public long Seconds;
        public long Nanoseconds;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PollFd
    {
        public int FileDescriptor;
        public short Events;
        public short ReturnedEvents;
    }

    public static int GetTid()
    {
        var tid = Syscall(186);
        Check(tid, "gettid");
        return checked((int)tid);
    }

    public static void Pin(int cpu)
    {
        ulong mask = 1UL << cpu;
        Check(SetAffinity(0, sizeof(ulong), ref mask), "sched_setaffinity");
        RequireCpu(cpu);
    }

    public static void RequireCpu(int cpu)
    {
        if (GetCpu() != cpu)
            throw new InvalidOperationException("Actor was observed off its fixed CPU.");
    }

    public static long MonotonicNs() => ClockNs(1);

    public static long ProcessCpuNs() => ClockNs(2);

    private static long ClockNs(int clock)
    {
        Check(ClockGetTime(clock, out var time), "clock_gettime");
        return checked(time.Seconds * 1_000_000_000 + time.Nanoseconds);
    }

    public static byte ReadByte(int fd)
    {
        long received;
        byte value;
        do
            received = SyscallRead(0, fd, out value, 1);
        while (received < 0 && Marshal.GetLastPInvokeError() == Interrupted);
        Check(received, "read");
        if (received != 1)
            throw new InvalidOperationException("Actor pipe ended before the expected byte.");
        return value;
    }

    public static void WriteByte(int fd, byte value)
    {
        nint written;
        do
            written = Write(fd, ref value, 1);
        while (written < 0 && Marshal.GetLastPInvokeError() == Interrupted);
        Check(written, "write");
        if (written != 1)
            throw new InvalidOperationException("Actor pipe did not accept the expected byte.");
    }

    public static void WaitReadable(int fd)
    {
        var poll = new PollFd { FileDescriptor = fd, Events = PollIn };
        var result = Poll(ref poll, 1, 2_000);
        Check(result, "poll");
        if (result != 1 || (poll.ReturnedEvents & PollIn) == 0)
            throw new TimeoutException("Worker did not acknowledge the pipe byte.");
    }

    public static void Check(long result, string operation)
    {
        if (result < 0)
            throw new InvalidOperationException($"{operation} failed with errno {Marshal.GetLastPInvokeError()}.");
    }
}
