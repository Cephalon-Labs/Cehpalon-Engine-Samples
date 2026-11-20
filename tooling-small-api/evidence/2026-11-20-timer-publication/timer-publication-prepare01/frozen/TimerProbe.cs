using System.Diagnostics;
using System.Runtime.InteropServices;

namespace MetricsOverhead;

// Synthetic diagnostics only. No HTTPS benchmark path calls this entrypoint.
public static class TimerProbe
{
    private readonly record struct Point(int Kind, long Before, long After, int NativeTid, int ManagedTid, long Pending, int Threads);
    private sealed class Trial(int profile, int index)
    {
        public int Profile { get; } = profile;
        public int Index { get; } = index;
        public string Status { get; set; } = "started";
        public string? FailureType { get; set; }
        public bool Accepted { get; set; }
        public bool RegisteredIncomplete { get; set; }
        public bool CallbackCompleted { get; set; }
        public bool TimerDisposed { get; set; }
        public Dictionary<string, Point> Points { get; } = new(StringComparer.Ordinal);
    }
    [DllImport("kernel32.dll")] private static extern uint GetCurrentThreadId();

    private static Point Stamp(int kind, int profile, int index)
    {
        var tid = checked((int)GetCurrentThreadId());
        var managed = Environment.CurrentManagedThreadId;
        var pending = ThreadPool.PendingWorkItemCount;
        var threads = ThreadPool.ThreadCount;
        var before = Entry.Now;
        Diagnostic.Mark(kind, profile, index);
        return new(kind, before, Entry.Now, tid, managed, pending, threads);
    }

    public static async Task<int> Run(Dictionary<string, string> options)
    {
        var count = options.GetValueOrDefault("--probe-mode") switch
        {
            "conformance" => 8, "compare" => 128, _ => throw new ArgumentException()
        };
        var trials = new List<Trial>(count * 4);
        var status = "failed";
        string? failure = null;
        try
        {
            for (var profile = 1; profile <= 4; profile++)
            for (var index = 0; index < count; index++)
            {
                var trial = new Trial(profile, index); trials.Add(trial);
                try
                {
                    if (profile == 1)
                    {
                        trial.Points["delay_before"] = Stamp(78, profile, index);
                        await Task.Delay(1).ConfigureAwait(false);
                        trial.Points["resume"] = Stamp(79, profile, index);
                    }
                    else await Complete(trial);
                    trial.Points["end"] = Stamp(80, profile, index);
                    trial.Status = "passed";
                }
                catch (Exception error)
                {
                    trial.Status = "failed"; trial.FailureType = error.GetType().Name; throw;
                }
            }
            status = "passed";
        }
        catch (Exception error) { failure = error.GetType().Name; }
        finally
        {
            await Entry.Save(options["--output"], new { status, failureType = failure,
                mode = options["--probe-mode"], observed = Diagnostic.Enabled, countPerProfile = count,
                requestedTimerMilliseconds = 1, environment = Entry.EnvironmentInfo(), trials });
        }
        return status == "passed" ? 0 : 1;
    }

    private static async Task Complete(Trial trial)
    {
        var profile = trial.Profile; var index = trial.Index;
        var points = trial.Points;
        // Separate writer slots until all tasks have joined: Dictionary is not a concurrent publication channel.
        Point callback = default, publishBefore = default, publishAfter = default, resume = default;
        var completion = new TaskCompletionSource(profile == 3 ? TaskCreationOptions.None : TaskCreationOptions.RunContinuationsAsynchronously);
        var callbackDone = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Exception? callbackError = null;
        async Task AwaitCompletion()
        {
            await completion.Task.ConfigureAwait(false);
            resume = Stamp(77, profile, index);
        }
        void Callback()
        {
            try
            {
                callback = Stamp(74, profile, index);
                publishBefore = Stamp(75, profile, index);
                if (!completion.TrySetResult()) throw new InvalidOperationException();
                publishAfter = Stamp(76, profile, index);
            }
            catch (Exception error) { callbackError = error; completion.TrySetException(error); }
            finally { callbackDone.TrySetResult(); }
        }

        using var timer = profile == 4 ? null : new Timer(_ => Callback(), null, Timeout.Infinite, Timeout.Infinite);
        var awaited = AwaitCompletion();
        trial.RegisteredIncomplete = !completion.Task.IsCompleted && !awaited.IsCompleted;
        if (!trial.RegisteredIncomplete) throw new InvalidOperationException();
        points["registered"] = Stamp(71, profile, index);
        try
        {
            points["arm_before"] = Stamp(72, profile, index);
            trial.Accepted = profile == 4 ? ThreadPool.QueueUserWorkItem(_ => Callback()) : timer!.Change(1, Timeout.Infinite);
            points["arm_after"] = Stamp(73, profile, index);
            if (!trial.Accepted) throw new InvalidOperationException();
            await awaited.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false);
            await callbackDone.Task.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false);
            trial.CallbackCompleted = true;
            if (callbackError is not null) throw callbackError;
        }
        finally
        {
            if (timer is not null)
            {
                await timer.DisposeAsync();
                trial.TimerDisposed = true;
                points["disposed"] = Stamp(81, profile, index);
            }
            points["callback"] = callback;
            points["publish_before"] = publishBefore;
            points["publish_after"] = publishAfter;
            points["resume"] = resume;
        }
    }
}
