using System.Diagnostics;
using System.Diagnostics.Tracing;
using System.Runtime.InteropServices;
using System.Text.Json;

if(args.Length==0 || args.Length==1 && args[0] is "--help" or "-h") {Console.WriteLine("Usage: TaskConformance <new-output.json>. Use the owned TPL collector controller for diagnostic evidence.");return 0;}
var output = Path.GetFullPath(args.Single());
if (File.Exists(output) || File.Exists(output + ".points.jsonl")) throw new IOException("Output must be new.");
var cases = new List<object>();
var start = Stopwatch.GetTimestamp();
try
{
    RunBlocked("scheduled", "success");
    const string completed = "completed-before-wait";
    Journal.Point(completed, "case.start", 0, 0);
    var done = Task.FromResult(42);
    Journal.Point(completed, "task.bound", done.Id, TaskScheduler.Default.Id);
    Journal.Point(completed, "wait.begin", done.Id, TaskScheduler.Default.Id);
    var answer = done.GetAwaiter().GetResult();
    Journal.Point(completed, "wait.end", done.Id, TaskScheduler.Default.Id);
    Require(answer == 42 && done.IsCompletedSuccessfully, "Completed result");
    Journal.Point(completed, "case.end", done.Id, TaskScheduler.Default.Id);
    cases.Add(new { name=completed, taskId=done.Id, schedulerId=TaskScheduler.Default.Id, outcome="success", result=answer, expectedTaskWait=false });
    RunBlocked("synchronous-block", "success");

    const string inline="forced-inline";
    Journal.Point(inline, "case.start", 0, 0);
    var scheduler = new InlineScheduler();
    var caller = Journal.NativeTid();
    var task = new Task<int>(() => { Journal.Point(inline,"task.body.enter", Task.CurrentId!.Value, TaskScheduler.Current.Id); Journal.Point(inline,"task.body.exit",Task.CurrentId!.Value,TaskScheduler.Current.Id); return 43; });
    Journal.Point(inline,"task.bound",task.Id,scheduler.Id);
    task.Start(scheduler);
    Require(!task.IsCompleted, "Queued inline fixture cannot complete before wait");
    Journal.Point(inline,"wait.begin",task.Id,scheduler.Id);
    var value=task.GetAwaiter().GetResult();
    Journal.Point(inline,"wait.end",task.Id,scheduler.Id);
    Require(value==43 && scheduler.InlineCount==1 && scheduler.InlineTid==caller && scheduler.QueuedTask==task, "Forced inline semantic proof");
    Journal.Point(inline,"case.end",task.Id,scheduler.Id);
    cases.Add(new { name=inline, taskId=task.Id, schedulerId=scheduler.Id, outcome="success", inlineNativeTid=caller, inlineCount=scheduler.InlineCount, expectedTaskWait=true });

    const string nested="nested";
    Journal.Point(nested,"case.start",0,0);
    using(var gate=new ManualResetEventSlim())
    using(var childEntered=new ManualResetEventSlim())
    using(var parentWaiting=new ManualResetEventSlim())
    {
        int childId=0, childTid=0;
        var parent=Task.Run(() => {
            Journal.Point(nested,"task.body.enter",Task.CurrentId!.Value,TaskScheduler.Current.Id);
            var child=Task.Run(() => { childTid=Journal.NativeTid(); Journal.Point(nested,"task.body.enter",Task.CurrentId!.Value,TaskScheduler.Current.Id); childEntered.Set(); Require(gate.Wait(10000),"Nested gate");Journal.Point(nested,"task.body.exit",Task.CurrentId!.Value,TaskScheduler.Current.Id);return 44; });
            childId=child.Id; Journal.Point(nested,"task.bound",child.Id,TaskScheduler.Default.Id);
            Require(childEntered.Wait(10000),"Child entered");
            Journal.Point(nested,"wait.begin",child.Id,TaskScheduler.Default.Id);parentWaiting.Set();
            var n=child.GetAwaiter().GetResult(); Journal.Point(nested,"wait.end",child.Id,TaskScheduler.Default.Id);
            Journal.Point(nested,"task.body.exit",Task.CurrentId!.Value,TaskScheduler.Current.Id);return n;
        });
        Journal.Point(nested,"task.bound",parent.Id,TaskScheduler.Default.Id);
        Require(parentWaiting.Wait(10000),"Parent already executing on worker");
        var release=new Thread(()=> { Thread.Sleep(75);gate.Set(); });
        release.Start();
        try { Journal.Point(nested,"wait.begin",parent.Id,TaskScheduler.Default.Id);Require(parent.GetAwaiter().GetResult()==44,"Nested value");Journal.Point(nested,"wait.end",parent.Id,TaskScheduler.Default.Id); }
        finally { gate.Set(); Require(release.Join(10000),"Nested releaser joined"); }
        Require(parent.IsCompletedSuccessfully && childId>0 && childId!=parent.Id && childTid>0,"Nested semantics");
        Journal.Point(nested,"case.end",parent.Id,TaskScheduler.Default.Id);
        cases.Add(new { name=nested, taskId=parent.Id,childTaskId=childId,schedulerId=TaskScheduler.Default.Id,outcome="success",expectedTaskWait=true });
    }
    RunBlocked("exception", "exception");
    RunBlocked("cancellation", "canceled");
    var elapsed=Stopwatch.GetTimestamp()-start;
    Journal.Save(output+".points.jsonl");
    using var stream=new FileStream(output,FileMode.CreateNew,FileAccess.Write,FileShare.Read);
    JsonSerializer.Serialize(stream,new { status="passed",role="synthetic_task_conformance_not_benchmark", processId=Environment.ProcessId, mainNativeTid=Journal.MainTid,frequency=Stopwatch.Frequency, elapsedTicks=elapsed,cases, ownedThreadsJoined=true, runtime=RuntimeInformation.FrameworkDescription });
    return 0;
}
catch(Exception e)
{
    Journal.Save(output+".points.jsonl");
    using var stream=new FileStream(output,FileMode.CreateNew,FileAccess.Write,FileShare.Read);
    JsonSerializer.Serialize(stream,new {status="failed",failure=e.ToString(),cases});return 1;
}

void RunBlocked(string name,string outcome)
{
    Journal.Point(name,"case.start",0,0);
    using var entered=new ManualResetEventSlim();using var gate=new ManualResetEventSlim();using var waiting=new ManualResetEventSlim();using var cancellation=new CancellationTokenSource();
    var workerTid=0;
    var t=Task.Run(() => { workerTid=Journal.NativeTid();Journal.Point(name,"task.body.enter",Task.CurrentId!.Value,TaskScheduler.Current.Id);entered.Set();Require(gate.Wait(10000),"Owned task gate");Journal.Point(name,"task.body.exit",Task.CurrentId!.Value,TaskScheduler.Current.Id);if(outcome=="exception") throw new FixtureException();if(outcome=="canceled") cancellation.Token.ThrowIfCancellationRequested();return 42; },cancellation.Token);
    Journal.Point(name,"task.bound",t.Id,TaskScheduler.Default.Id);
    Require(entered.Wait(10000),"Owned task entered");
    var release=new Thread(()=> { Require(waiting.Wait(10000),"Caller wait announced");Thread.Sleep(75);if(outcome=="canceled")cancellation.Cancel();gate.Set(); });release.Start();
    var observed="success";var result=0;
    try { Journal.Point(name,"wait.begin",t.Id,TaskScheduler.Default.Id);waiting.Set();try {result=t.GetAwaiter().GetResult();}catch(FixtureException){observed="exception";}catch(OperationCanceledException){observed="canceled";}finally{Journal.Point(name,"wait.end",t.Id,TaskScheduler.Default.Id);} }
    finally { gate.Set();Require(release.Join(10000),"Owned releaser joined"); }
    Require(observed==outcome && workerTid>0 && workerTid!=Journal.MainTid,"Task semantic outcome");
    Require(outcome=="success"?t.IsCompletedSuccessfully&&result==42:outcome=="exception"?t.IsFaulted:t.IsCanceled,"Task terminal state");
    Journal.Point(name,"case.end",t.Id,TaskScheduler.Default.Id);
    cases.Add(new { name, taskId=t.Id,schedulerId=TaskScheduler.Default.Id,outcome,workerNativeTid=workerTid,expectedTaskWait=true });
}
static void Require(bool value,string message) {if(!value)throw new InvalidOperationException(message);}
sealed class FixtureException:Exception;
sealed class InlineScheduler:TaskScheduler
{
    public int InlineCount,InlineTid;public Task? QueuedTask;
    protected override void QueueTask(Task task) {if(QueuedTask is not null)throw new InvalidOperationException("One task fixture");QueuedTask=task;}
    protected override bool TryExecuteTaskInline(Task task,bool wasQueued) {if(!wasQueued||task!=QueuedTask)return false;InlineCount++;InlineTid=Journal.NativeTid();return TryExecuteTask(task);}
    protected override IEnumerable<Task>? GetScheduledTasks()=>QueuedTask is null?Array.Empty<Task>():[QueuedTask];
}
static class Journal
{
    static readonly object Sync=new();static readonly List<object> Points=[];static long sequence;
    internal static readonly int MainTid=NativeTid();
    [DllImport("libc",EntryPoint="gettid")]static extern int GetTid();
    [DllImport("kernel32.dll")]static extern uint GetCurrentThreadId();
    internal static int NativeTid()=>OperatingSystem.IsWindows()?checked((int)GetCurrentThreadId()):GetTid();
    internal static void Point(string caseName,string kind,int taskId,int schedulerId)
    {
        lock(Sync)
        {
            var n=++sequence;var pid=Environment.ProcessId;var tid=NativeTid();var ticks=Stopwatch.GetTimestamp();var utcBefore=Stopwatch.GetTimestamp();var utc=DateTimeOffset.UtcNow.UtcTicks;var utcAfter=Stopwatch.GetTimestamp();var markerBefore=Stopwatch.GetTimestamp();
            FixtureEvents.Log.Point(n,caseName,kind,taskId,schedulerId,pid,tid,ticks,Stopwatch.Frequency);
            var markerAfter=Stopwatch.GetTimestamp();
            Points.Add(new {sequence=n,caseName,kind,taskId,schedulerId,processId=pid,nativeTid=tid,stopwatchTicks=ticks,frequency=Stopwatch.Frequency,markerBeforeTicks=markerBefore,markerAfterTicks=markerAfter,utcTicks=utc,utcBeforeTicks=utcBefore,utcAfterTicks=utcAfter});
        }
    }
    internal static void Save(string path){lock(Sync){using var w=new StreamWriter(new FileStream(path,FileMode.CreateNew));foreach(var point in Points)w.WriteLine(JsonSerializer.Serialize(point));}}
}
[EventSource(Name="Cehpalon-Task-Conformance")]
sealed class FixtureEvents:EventSource
{
    internal static readonly FixtureEvents Log=new();
    public static class Keywords { public const EventKeywords Diagnostic=(EventKeywords)1; }
    [Event(1,Level=EventLevel.Informational,Keywords=Keywords.Diagnostic)]
    public void Point(long sequence,string caseName,string kind,int taskId,int schedulerId,int processId,int nativeTid,long stopwatchTicks,long frequency)
    {if(IsEnabled())WriteEvent(1,sequence,caseName,kind,taskId,schedulerId,processId,nativeTid,stopwatchTicks,frequency);}
}
