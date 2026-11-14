"""Independent adverse task-lifetime fixtures; no builds/captures or primary edits."""
from copy import deepcopy
import argparse, hashlib, importlib.util, json, sys
from pathlib import Path

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[1])
parser.add_argument('--output',required=True,type=Path)
parser.add_argument('--capture',type=Path)
args=parser.parse_args()
SOURCE=args.root/'tools/analyze_tooling_tasks.py'

spec=importlib.util.spec_from_file_location('root_tasks', SOURCE)
tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(tool)
PROVIDER='System.Threading.Tasks.TplEventSource'
GOOD={'status':'completed','eventsLost':0,'etlxEventsLost':0,'payloadReadErrors':0,'events':5}
versions={7:1,8:0,9:1,10:3,11:0}

def event(event_id, task=5, tid=100, timestamp=0, scheduler=1, origin=0):
    payload={'OriginatingTaskSchedulerID':scheduler,'OriginatingTaskID':origin,'TaskID':task}
    if event_id==7:payload.update(CreatingTaskID=0,TaskCreationOptions=0,appDomain=1)
    if event_id==9:payload.update(IsExceptional=False)
    if event_id==10:payload.update(Behavior=1,ContinueWithTaskID=0)
    return dict(provider=PROVIDER,name='fixture',processId=77,threadId=tid,timeMsec=timestamp,
                eventId=event_id,opcode=9 if event_id in [7,10] else 0,
                version=versions.get(event_id,0),templateType='DynamicTraceEventData',payload=payload)

def sequence(task=5):
    return [event(7,task,100,0,scheduler=2), event(10,task,100,1,scheduler=1),
            event(8,task,200,2,scheduler=1), event(9,task,200,3,scheduler=1),
            event(11,task,100,4,scheduler=1)]

def run(events):return tool.analyze(events,{**GOOD,'events':len(events)},77)
def complete(result,task=5):return any(t['task_id']==task and t['status']=='complete_observed_lifetime' for t in result['tasks'])
def rejects(result,task=5):return task in result['poisoned_task_ids'] and not complete(result,task)
def raises(fn):
    try:fn()
    except (ValueError,TypeError):return True
    return False

checks=[]
def check(name,fn):
    try:
        assert fn()
        checks.append(dict(name=name,status='passed'))
    except Exception as error:checks.append(dict(name=name,status='failed',error=repr(error)))

x=sequence();r=run(x)
check('valid_execution_and_wait_retained',lambda:complete(r) and len(r['waits'])==1 and not r['errors'])
check('destination_and_ambient_scheduler_are_distinct',lambda:r['tasks'][0]['destination_scheduler_id']==2 and r['tasks'][0]['start']['event']['payload']['OriginatingTaskSchedulerID']==1)
check('wait_context_not_destination_scheduler',lambda:r['waits'][0]['linked_complete_lifetime'])
check('no_CPU_blocked_scheduler_duration',lambda:r['tasks'][0]['cpu_time_ms'] is None and all(r['waits'][0][k] is None for k in ['blocked_time_ms','scheduler_delay_ms']))
inline=sequence()
for z in inline:z['threadId']=100
ir=run(inline)
check('inline_execution_can_be_within_wait_same_TID',lambda:complete(ir) and ir['tasks'][0]['execution_native_tid']==100 and ir['waits'][0]['caller_native_tid']==100)
exception=sequence();exception[3]['payload']['IsExceptional']=True
check('fault_flag_retained_without_denial',lambda:complete(run(exception)) and run(exception)['tasks'][0]['complete']['event']['payload']['IsExceptional'])
nested=[event(7,5,100,0),event(8,5,100,1),event(7,6,100,2),event(10,6,100,3,origin=5),event(8,6,100,4,origin=5),event(9,6,100,5,origin=5),event(11,6,100,6,origin=5),event(9,5,100,7)]
check('nested_inline_execution_same_TID_has_two_lifetimes',lambda:all(complete(run(nested),t) for t in [5,6]))
check('already_completed_task_without_schedule_stays_absent',lambda:not run([])['tasks'] and not run([])['waits'])
for missing in [2,3]:
 y=sequence();del y[missing]
 check('missing_execution_phase_'+str(missing),lambda y=y:not complete(run(y)))
y=[event(7)]
check('scheduled_but_unexecuted_is_unknown',lambda:run(y)['tasks'][0]['status']=='unfinished_or_unexecuted_unknown')
y=sequence()[:-1]
check('unfinished_wait_remains_unknown',lambda:len(run(y)['unfinished_waits'])==1 and not run(y)['waits'])
y=sequence()+[event(7,timestamp=5),event(8,timestamp=6),event(9,timestamp=7)]
check('reused_task_ID_poison_entire_lifetime',lambda:rejects(run(y)))
y=sequence();y.insert(1,event(7,timestamp=0))
check('duplicate_schedule_poison_persists',lambda:rejects(run(y)))
y=sequence();y.insert(3,event(8,tid=200,timestamp=2))
check('duplicate_start_poison_persists',lambda:rejects(run(y)))
y=sequence();y[3]['threadId']=201
check('execution_native_TID_change_rejected',lambda:rejects(run(y)))
y=sequence();y[3]['payload']['OriginatingTaskID']=1
check('execution_origin_task_change_rejected',lambda:rejects(run(y)))
y=sequence();y[3]['payload']['OriginatingTaskSchedulerID']=2
check('execution_origin_scheduler_change_rejected',lambda:rejects(run(y)))
y=sequence();y[4]['threadId']=101
check('wait_end_different_caller_rejected',lambda:rejects(run(y)))
y=sequence();y[4]['payload']['OriginatingTaskID']=3
check('wait_end_different_origin_rejected',lambda:rejects(run(y)))
y=sequence();y.insert(2,event(10,timestamp=1))
check('duplicate_wait_begin_rejected',lambda:rejects(run(y)))
y=sequence();y[3]['timeMsec']=1
check('clock_reversal_rejected',lambda:rejects(run(y)))
y=sequence();y[1]['payload']['Behavior']=2
check('async_wait_not_same_thread_duration',lambda:run(y)['waits'][0]['status']=='asynchronous_wait_not_same_thread_duration' and run(y)['waits'][0]['blocked_time_ms'] is None)
for field,bad in [('version',False),('version',99),('opcode',0),('eventId','7'),('eventId',7.0),('templateType',''),('timeMsec',True),('timeMsec',float('nan')),('timeMsec',-1),('threadId',True),('threadId',0),('processId',True),('processId',88)]:
 y=sequence();y[0][field]=bad
 check('bad_header_'+field+'_'+repr(bad),lambda y=y:bool(run(y)['errors']) and not complete(run(y)))
for field,bad in [('TaskID',True),('TaskID',0),('TaskID',-1),('TaskID',2**31),('OriginatingTaskSchedulerID',0),('OriginatingTaskID',-1),('CreatingTaskID',True),('TaskCreationOptions',-1),('appDomain',0)]:
 y=sequence();y[0]['payload'][field]=bad
 check('bad_payload_'+field+'_'+repr(bad),lambda y=y:bool(run(y)['errors']) and not complete(run(y)))
y=sequence();y[3]['payload']['IsExceptional']=1
check('exception_flag_requires_bool',lambda:rejects(run(y)))
y=sequence();y[1]['payload']['Behavior']=True
check('wait_behavior_requires_integer_not_bool',lambda:rejects(run(y)))
y=sequence();y[1]['payload']['ContinueWithTaskID']=-1
check('negative_continuation_rejected',lambda:rejects(run(y)))
for field in ['eventsLost','etlxEventsLost','payloadReadErrors']:
 for bad in [1,False,0.0,None]:
  report=deepcopy(GOOD);report[field]=bad
  check('quality_gate_'+field+'_'+repr(bad),lambda report=report:raises(lambda:tool.analyze(sequence(),report,77)))
y=sequence();y.insert(0,event(12,timestamp=0))
check('well_typed_other_TPL_ID_is_counted_not_lifecycle',lambda:complete(run(y)) and run(y)['ignored_event_ids'].get('12')==1)
for alias in [5.0,'5']:
 y=sequence();bad=event(8,task=alias,tid=200,timestamp=1.5);y.insert(2,bad)
 check('malformed_compatible_task_key_persists_'+repr(alias),lambda y=y:rejects(run(y)))
y=sequence(task=1);bad=event(8,task=True,tid=200,timestamp=1.5);y.insert(2,bad)
check('malformed_bool_compatible_task_key_persists',lambda:rejects(run(y),1))
for bad_id in [0,-1]:
 y=sequence();y.insert(2,event(bad_id,task=5,timestamp=1.5))
 check('nonpositive_event_id_is_not_ignored_'+str(bad_id),lambda y=y:bool(run(y)['errors']) and not complete(run(y)))
for count in [4,6,False,5.0]:
 report={**GOOD,'events':count}
 check('raw_count_gate_'+repr(count),lambda report=report:raises(lambda:tool.analyze(sequence(),report,77)))
check('raw_nonobject_is_not_silently_skipped',lambda:raises(lambda:tool.analyze([None],{**GOOD,'events':1},77)))
if args.capture:
 sys.path.insert(0,str(args.root/'tools'))
 import verify_task_conformance as verifier
 folder=args.capture
 paths={'events':folder/'analysis/events.jsonl','analysis':folder/'analysis/summary.json','capture':folder/'capture.json','target':folder/'target.json','points':folder/'target.json.points.jsonl'}
 data={k:verifier.lines(p) if k in ['events','points'] else verifier.read(p) for k,p in paths.items()}
 def positive_or_mutated(mutator=None):
  x=deepcopy(data)
  if mutator:mutator(x)
  return verifier.verify(x['events'],x['analysis'],x['capture'],x['target'],x['points'])
 check('real_positive_fixture_verifies',lambda:positive_or_mutated()['status']=='passed_bounded_synthetic_conformance')
 def marker(x):return next(e for e in x['events'] if e.get('provider')==verifier.MARKER)
 for field,bad in [('eventId',True),('eventId',1.0),('version',False),('opcode',False)]:
  check('marker_exact_integer_header_'+field+'_'+repr(bad),lambda field=field,bad=bad:raises(lambda:positive_or_mutated(lambda x:marker(x).__setitem__(field,bad))))
 check('missing_marker_rejected',lambda:raises(lambda:positive_or_mutated(lambda x:x['events'].remove(marker(x)))))
 check('sidecar_sequence_gap_rejected',lambda:raises(lambda:positive_or_mutated(lambda x:x['points'][0].__setitem__('sequence',999))))
 check('target_semantic_fail_rejected',lambda:raises(lambda:positive_or_mutated(lambda x:x['target'].__setitem__('status','failed'))))
 check('target_threads_unjoined_rejected',lambda:raises(lambda:positive_or_mutated(lambda x:x['target'].__setitem__('ownedThreadsJoined',False))))
 check('target_case_order_drift_rejected',lambda:raises(lambda:positive_or_mutated(lambda x:x['target']['cases'].reverse())))
 check('capture_PID_drift_rejected',lambda:raises(lambda:positive_or_mutated(lambda x:x['capture'].__setitem__('target_pid',1))))
 check('marker_thread_drift_rejected',lambda:raises(lambda:positive_or_mutated(lambda x:marker(x).__setitem__('threadId',1))))
 check('marker_payload_drift_rejected',lambda:raises(lambda:positive_or_mutated(lambda x:marker(x)['payload'].__setitem__('taskId',999))))
 check('marker_clock_bracket_reversal_rejected',lambda:raises(lambda:positive_or_mutated(lambda x:x['points'][0].__setitem__('markerAfterTicks',x['points'][0]['markerBeforeTicks']-1))))
 def move_finish_thread(x):
  point=next(p for p in x['points'] if p['kind']=='wait.end' and p['caseName']=='synchronous-block')
  sequence=point['sequence'];new_tid=point['nativeTid']+99999;point['nativeTid']=new_tid
  m=next(e for e in x['events'] if e.get('provider')==verifier.MARKER and e['payload']['sequence']==sequence)
  m['threadId']=new_tid;m['payload']['nativeTid']=new_tid
 check('wait_end_marker_other_thread_rejected',lambda:raises(lambda:positive_or_mutated(move_finish_thread)))
report=dict(status='passed' if all(c['status']=='passed' for c in checks) else 'failed',checks=len(checks),failed=sum(c['status']!='passed' for c in checks),results=checks,source_sha256=hashlib.sha256(SOURCE.read_bytes()).hexdigest(),scope='Independent pure fixtures only; no actual event delivery or causal claim')
report['fixture_source_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
if args.capture:
 report['verifier_source_sha256']=hashlib.sha256((args.root/'tools/verify_task_conformance.py').read_bytes()).hexdigest()
 report['capture_inputs_sha256']={k:hashlib.sha256(p.read_bytes()).hexdigest() for k,p in paths.items()}
with args.output.open('x',encoding='utf-8',newline='\n') as stream:stream.write(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items() if k!='results'}))
raise SystemExit(0 if report['failed']==0 else 1)
