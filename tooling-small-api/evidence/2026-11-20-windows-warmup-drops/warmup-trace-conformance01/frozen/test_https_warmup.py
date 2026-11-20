import copy
import unittest

from analyze_https_warmup import overlap, gc_episodes, task_envelopes, validate_trace
from trace_https_warmup import environment


def gc(name, qpc, pid=7, reason=1):
    return {'provider':'Microsoft-Windows-DotNETRuntime','name':'GC/'+name,'pid':pid,'qpc':qpc,'payload':{'ClrInstanceID':1,'Reason':reason}}


class EvidenceTests(unittest.TestCase):
    def valid_markers(self):
        events=[];records=[]
        for seq,kind,qpc,tid in [(1,1,1000,11),(2,2,2000,12)]:
            p={'sequence':seq,'ticks':qpc,'pid':7,'nativeTid':tid,'managedTid':13,'kind':kind,'phase':0,'index':-1,'lane':-1}
            events.append({'provider':'Cehpalon-Https-Warmup','pid':7,'tid':tid,'qpc':qpc,'milliseconds':(qpc-1000)/1000,'payload':p})
            records.append({'Sequence':seq,'Kind':kind,'Phase':0,'Index':-1,'Lane':-1,'Pid':7,'NativeTid':tid,'ManagedTid':13,'BeforeTicks':qpc,'AfterTicks':qpc+2})
        return events,{'expectedPid':7,'reportedEventsLost':0,'payloadReadErrors':0},{'pid':7,'frequency':1000000,'markerCount':2,'overflow':0,'late':0,'receipts':records}
    def test_clock_receipts_accept_exact_positive(self):
        self.assertEqual(validate_trace(*self.valid_markers())['pid'],7)
    def test_marker_mutations_rejected(self):
        mutations=[lambda e,s,r:e.pop(),lambda e,s,r:e[1]['payload'].__setitem__('sequence',1),
                   lambda e,s,r:e[0].__setitem__('pid',8),lambda e,s,r:e[0].__setitem__('tid',99),
                   lambda e,s,r:r['receipts'][0].__setitem__('AfterTicks',999),
                   lambda e,s,r:r.__setitem__('frequency',2000000),lambda e,s,r:s.__setitem__('reportedEventsLost',1),
                   lambda e,s,r:r.__setitem__('overflow',1),lambda e,s,r:r.__setitem__('late',1),
                   lambda e,s,r:s.__setitem__('payloadReadErrors',1),lambda e,s,r:r.__setitem__('frequency',0)]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                data=self.valid_markers();mutate(*data)
                with self.assertRaises(ValueError):validate_trace(*data)
    def test_clipped_union_does_not_double_count(self):
        self.assertEqual(overlap(10,30,[(0,15),(12,20),(25,40)]),15)
    def test_reversed_window_rejected(self):
        with self.assertRaises(ValueError):overlap(20,10,[])
    def test_four_gc_phases(self):
        values=[gc(n,t) for n,t in [('SuspendEEStart',10),('SuspendEEStop',12),('RestartEEStart',18),('RestartEEStop',20)]]
        episodes,errors=gc_episodes(values);self.assertEqual(errors,[]);self.assertEqual(episodes[0]['stop'],12)
    def test_gc_process_scope(self):
        episodes,errors=gc_episodes([gc('SuspendEEStart',10),gc('SuspendEEStop',12,8),gc('RestartEEStart',18),gc('RestartEEStop',20)])
        self.assertFalse(episodes);self.assertTrue(errors)
    def test_duplicate_poison_is_persistent(self):
        values=[gc(n,t) for n,t in [('SuspendEEStart',10),('SuspendEEStart',11),('SuspendEEStop',12),('RestartEEStart',18),('RestartEEStop',20),('SuspendEEStart',30),('SuspendEEStop',31),('RestartEEStart',32),('RestartEEStop',33)]]
        self.assertFalse(gc_episodes(values)[0])
    def test_incomplete_gc_not_a_pause(self):
        self.assertFalse(gc_episodes([gc('SuspendEEStart',1),gc('RestartEEStop',3)])[0])
    def test_task_reuse_not_promoted(self):
        def e(name,t):return {'provider':'System.Threading.Tasks.TplEventSource','name':name,'pid':7,'qpc':t,'tid':1,'payload':{'TaskID':3}}
        pairs,errors=task_envelopes([e('TaskScheduled',1),e('TaskScheduled',2),e('TaskStarted',3)])
        self.assertFalse(pairs);self.assertTrue(errors)
    def test_disabled_ipc_respected(self):
        with self.assertRaises(ValueError):environment({'dotnet_EnableDiagnostics_IPC':'0'})
    def test_case_insensitive_child_aliases(self):
        result,removed=environment({'dotnet_diagnosticports':'private','KEEP':'yes'})
        self.assertEqual(removed,['dotnet_diagnosticports']);self.assertNotIn('dotnet_diagnosticports',result);self.assertEqual(result['KEEP'],'yes')


if __name__=='__main__':unittest.main()
