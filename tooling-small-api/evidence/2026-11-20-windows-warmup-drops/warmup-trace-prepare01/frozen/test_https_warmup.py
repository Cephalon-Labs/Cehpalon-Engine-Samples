import copy
import unittest

from analyze_https_warmup import overlap, gc_episodes, task_envelopes, validate_trace
from trace_https_warmup import environment


def gc(name, qpc, pid=7, reason=1):
    return {'provider':'Microsoft-Windows-DotNETRuntime','name':'GC/'+name,'pid':pid,'qpc':qpc,'payload':{'ClrInstanceID':1,'Reason':reason}}


class EvidenceTests(unittest.TestCase):
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
