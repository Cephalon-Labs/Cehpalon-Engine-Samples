"""Independent ADR0024 portable offline ordering fixtures; no workload/build/capture."""
import argparse
from copy import deepcopy
import hashlib,importlib.util,json,subprocess,sys
from pathlib import Path
P=argparse.ArgumentParser();P.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[1]);P.add_argument('--output',type=Path,required=True);args=P.parse_args();sys.path.insert(0,str(args.root/'tools'));import analyze_roslyn_task_ordering as tool
checks=[]
def check(name,fn):
 try:assert fn();checks.append({'name':name,'status':'passed'})
 except Exception as e:checks.append({'name':name,'status':'failed','error':repr(e)})
def raises(fn):
 try:fn()
 except (ValueError,TypeError,KeyError):return True
 return False
pid=77
versions={7:1,8:0,9:1,10:3,11:0}
def event(event_id,time,tid=100,task=5,scheduler=1,origin=0):
 p={'TaskID':task,'OriginatingTaskSchedulerID':scheduler,'OriginatingTaskID':origin}
 if event_id==7:p.update(CreatingTaskID=0,TaskCreationOptions=0,appDomain=1)
 if event_id==9:p['IsExceptional']=False
 if event_id==10:p.update(Behavior=1,ContinueWithTaskID=0)
 return dict(provider=tool.tpl.PROVIDER,eventId=event_id,version=versions[event_id],opcode=9 if event_id in [7,10]else 0,templateType='Microsoft.Diagnostics.Tracing.Parsers.DynamicTraceEventData',processId=pid,threadId=tid,timeMsec=time,payload=p)
def ref(event_id,time,tid=100,**kwargs):return {'raw_record_index':event_id,'event':event(event_id,time,tid,**kwargs)}
def models(schedule=1,start=2,complete=4,begin=3,end=5,caller=100,worker=200):
 state=dict(task_id=5,process_id=pid,status='complete_observed_lifetime',execution_native_tid=worker,schedule=ref(7,schedule,100,scheduler=2),start=ref(8,start,worker,scheduler=1),complete=ref(9,complete,worker,scheduler=1))
 wait=dict(task_id=5,caller_native_tid=caller,status='synchronous_wait_bracket_observed',behavior=1,begin=ref(10,begin,caller,scheduler=3),end=ref(11,end,caller,scheduler=3))
 return wait,state
def classify(**kwargs):w,s=models(**kwargs);return tool.classify_wait(w,s,pid)
check('literal_before',lambda:tool.relation(1,2)=='before')
check('literal_after',lambda:tool.relation(2,1)=='after')
check('equal_recorded_time_is_unresolved',lambda:tool.relation(1,1.0)==tool.TIE)
check('literal_float_decimal_not_tolerance',lambda:tool.relation(0.1+0.2,0.3)=='after')
for bad in [True,False,None,'1',-1,float('nan'),float('inf')]:
 check('malformed_timestamp_'+repr(bad),lambda bad=bad:raises(lambda:tool.relation(bad,1)))
r=classify()
check('four_literal_relations_preserved',lambda:[r[k]for k in tool.RELATIONS]==['before','before','after','before'])
check('separate_destination_execution_wait_schedulers_legal',lambda:r['status']=='literal_recorded_event_order')
check('different_execution_header_descriptive',lambda:r['execution_header_tid_relation']=='different_recorded_native_tid')
check('same_execution_header_descriptive_only',lambda:classify(worker=100)['execution_header_tid_relation']=='same_recorded_native_tid')
check('no_queue_CPU_blocked_scheduler_numbers',lambda:all(r[k]is None for k in ['queue_time_ms','cpu_time_ms','blocked_time_ms','scheduler_delay_ms']))
check('no_callsite_native_lifetime_proof',lambda:r['direct_waitforworkers_callsite_proven']is False and r['native_lifetime_proven']is False)
check('completion_event_after_waitend_legal',lambda:classify(complete=6)['execution_completion_vs_wait_end']=='after')
check('completion_event_before_waitbegin_legal',lambda:classify(complete=2.5)['execution_completion_vs_wait_begin']=='before')
check('execution_after_timeout_waitend_not_rejected',lambda:classify(start=6,complete=7)['execution_start_vs_wait_begin']=='after')
check('nonmain_wait_caller_kept',lambda:classify(caller=101)['caller_native_tid']==101)
check('equal_start_waitbegin_unresolved',lambda:classify(start=3)['execution_start_vs_wait_begin']==tool.TIE)
check('equal_completion_waitend_unresolved',lambda:classify(complete=5)['execution_completion_vs_wait_end']==tool.TIE)
w,s=models(start=3,complete=5);w['begin']['raw_record_index']=10000;w['end']['raw_record_index']=1
check('raw_index_not_equal_time_chronology_tiebreak',lambda:tool.classify_wait(w,s,pid)['execution_start_vs_wait_begin']==tool.TIE and tool.classify_wait(w,s,pid)['execution_completion_vs_wait_end']==tool.TIE)
for state_status in ['rejected_poisoned_identity','unfinished_or_unexecuted_unknown']:
 w,s=models();s['status']=state_status;check('unaccepted_context_unknown_'+state_status,lambda w=w,s=s:all(tool.classify_wait(w,s,pid)[k]==tool.UNKNOWN for k in tool.RELATIONS))
w,s=models();check('missing_execution_unknown',lambda:tool.classify_wait(w,None,pid)['status']==tool.UNKNOWN)
for role in ['schedule','start','complete']:
 w,s=models();s[role]=None;check('missing_phase_unknown_'+role,lambda w=w,s=s:tool.classify_wait(w,s,pid)['status']==tool.UNKNOWN)
for field,bad in [('task_id',True),('task_id',0),('task_id',5.0),('caller_native_tid',False),('caller_native_tid',0),('behavior',True),('behavior',3)]:
 w,s=models();w[field]=bad;check('wait_identity_'+field+'_'+repr(bad),lambda w=w,s=s:raises(lambda:tool.classify_wait(w,s,pid)))
for field,bad in [('task_id',True),('task_id',6),('process_id',True),('process_id',88),('execution_native_tid',False),('execution_native_tid',201)]:
 w,s=models();s[field]=bad;check('execution_identity_'+field+'_'+repr(bad),lambda w=w,s=s:raises(lambda:tool.classify_wait(w,s,pid)))
for role in ['begin','end']:
 for field,bad in [('processId',88),('threadId',101),('timeMsec',-1),('eventId',True),('version',False)]:
  w,s=models();w[role]['event'][field]=bad;check('wait_frame_'+role+'_'+field+'_'+repr(bad),lambda w=w,s=s:raises(lambda:tool.classify_wait(w,s,pid)))
for role in ['schedule','start','complete']:
 for field,bad in [('processId',88),('eventId',True),('opcode',False),('timeMsec',float('inf'))]:
  w,s=models();s[role]['event'][field]=bad;check('task_frame_'+role+'_'+field+'_'+repr(bad),lambda w=w,s=s:raises(lambda:tool.classify_wait(w,s,pid)))
w,s=models();s['start']['event']['payload']['TaskID']=6
check('execution_references_other_task_rejected',lambda:raises(lambda:tool.classify_wait(w,s,pid)))
w,s=models();s['complete']['event']['payload']['OriginatingTaskID']=2
check('execution_ambient_context_changed_rejected',lambda:raises(lambda:tool.classify_wait(w,s,pid)))
w,s=models();w['end']['event']['payload']['OriginatingTaskSchedulerID']=4
check('wait_origin_context_changed_rejected',lambda:raises(lambda:tool.classify_wait(w,s,pid)))
w,s=models();w['begin']['event']['payload']['Behavior']=2
check('wait_behavior_payload_model_mismatch_rejected',lambda:raises(lambda:tool.classify_wait(w,s,pid)))
w,s=models();w['status']='asynchronous_wait_not_same_thread_duration'
check('wait_status_behavior_mismatch_rejected',lambda:raises(lambda:tool.classify_wait(w,s,pid)))
for key,bad in [('IsExceptional',1)]:
 w,s=models();s['complete']['event']['payload'][key]=bad;check('completion_payload_'+key,lambda w=w,s=s:raises(lambda:tool.classify_wait(w,s,pid)))
for key,bad in [('CreatingTaskID',True),('TaskCreationOptions',-1),('appDomain',0)]:
 w,s=models();s['schedule']['event']['payload'][key]=bad;check('schedule_payload_'+key,lambda w=w,s=s:raises(lambda:tool.classify_wait(w,s,pid)))
check('execution_clock_reversal_rejected',lambda:raises(lambda:classify(schedule=3,start=2)))
check('wait_clock_reversal_rejected',lambda:raises(lambda:classify(begin=6,end=5)))
original=ref(7,1);raw=deepcopy(original['event'])
check('exact_raw_binding_accepted',lambda:tool.bind_reference(original,raw,7)is True)
for index in [True,-1,7.0,8]:
 check('raw_index_alias_or_drift_'+repr(index),lambda index=index:raises(lambda:tool.bind_reference(original,raw,index)))
for value in [True,7.0,-1]:
 x=deepcopy(original);x['raw_record_index']=value;check('copied_index_type_'+repr(value),lambda x=x:raises(lambda:tool.bind_reference(x,raw,7)))
for value in [0.0,False,1]:
 x=deepcopy(original);x['event']['payload']['OriginatingTaskID']=value;check('typed_nested_payload_drift_'+repr(value),lambda x=x:raises(lambda:tool.bind_reference(x,raw,7)))
x=deepcopy(original);x['event']['extra']='drift'
check('extra_copied_event_field_rejected',lambda:raises(lambda:tool.bind_reference(x,raw,7)))
check('typed_equal_preserves_numerical_type',lambda:not tool.typed_equal({'x':[1]}, {'x':[True]}) and not tool.typed_equal([1], [1.0]))
check('typed_equal_nan_never_matches',lambda:not tool.typed_equal(float('nan'),float('nan')))
# Retained negative CLI preparation proves reviewed-hash and raw-file hash drift fail closed.
artifacts=args.output.with_suffix('');artifacts.mkdir(exist_ok=False)
def cli_case(name,summary,expected):
 folder=artifacts/name;folder.mkdir();lineage=folder/'lineage';lineage.mkdir();capture=folder/'capture';capture.mkdir();(capture/'capture.json').write_text('{}',encoding='utf-8');summary_path=lineage/'summary.json';summary_path.write_text(json.dumps(summary),encoding='utf-8');digest=hashlib.sha256(summary_path.read_bytes()).hexdigest()
 run=subprocess.run([sys.executable,str(Path(tool.__file__)),'--capture',str(capture),'--lineage',str(lineage),'--expected-lineage-summary-sha256',digest if expected is None else expected,'--output',str(folder/'output')],capture_output=True,text=True,encoding='utf-8');(folder/'stdout.txt').write_text(run.stdout,encoding='utf-8');(folder/'stderr.txt').write_text(run.stderr,encoding='utf-8');return run
run=cli_case('reviewed-summary-hash-drift',{},'0'*64)
check('CLI_reviewed_summary_hash_drift_rejected',lambda:run.returncode!=0 and 'Reviewed lineage summary hash'in run.stderr)
run=cli_case('raw-input-hash-drift',{'status':'completed_bounded_context_observations','source_sha256':tool.LINEAGE_SHA,'assembler_sha256':tool.TPL_SHA,'inputs_sha256':{'capture.json':'0'*64},'outputs_sha256':{}},None)
check('CLI_raw_input_hash_drift_rejected',lambda:run.returncode!=0 and 'Lineage raw input hash capture.json'in run.stderr)
report={'status':'passed'if all(c['status']=='passed'for c in checks)else'failed','checks':len(checks),'failed':sum(c['status']!='passed'for c in checks),'results':checks,'ordering_source_sha256':hashlib.sha256(Path(tool.__file__).read_bytes()).hexdigest(),'fixture_source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'limits':['Portable offline/adverse fixtures only; no target/build/capture or causal/timing claims.']}
with args.output.open('x',encoding='utf-8',newline='\n')as f:f.write(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items()if k not in ['results','limits']}));raise SystemExit(0 if not report['failed']else 1)
