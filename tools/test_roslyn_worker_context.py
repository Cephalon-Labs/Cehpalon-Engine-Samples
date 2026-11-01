"""Independent ADR0025 portable pure frame/scope/dedup fixtures; no workload capture."""
import argparse
from copy import deepcopy
from fractions import Fraction
import hashlib,json,sys
from pathlib import Path
P=argparse.ArgumentParser();P.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[1]);P.add_argument('--output',type=Path,required=True);a=P.parse_args();sys.path.insert(0,str(a.root/'tools'));import analyze_roslyn_worker_context as tool
checks=[]
def check(name,fn):
 try:assert fn();checks.append(dict(name=name,status='passed'))
 except Exception as e:checks.append(dict(name=name,status='failed',error=repr(e)))
def raises(fn):
 try:fn()
 except (ValueError,TypeError,KeyError):return True
 return False
def labels(frames):return tool.classify_frames(frames)['labels']
compiler='Microsoft.CodeAnalysis.CSharp.MethodCompiler.CompileNamedType()'
other='Microsoft.CodeAnalysis.CSharp.Symbols.SourceNamespaceSymbol.ForceComplete()'
wait='System.Threading.WaitHandle.WaitOne()'
frames=[wait,compiler,other,'System.Threading.Monitor.Enter(System.Object)']
r=tool.classify_frames(frames)
check('compiler_wait_and_other_namespace_coexist',lambda:r['labels']==['managed_wait_entry_frame','other_codeanalysis_frame','roslyn_method_compiler_frame'])
check('multiple_wait_frames_not_exclusive_labels',lambda:sum(x['label']=='managed_wait_entry_frame'for x in r['matches'])==2 and r['labels'].count('managed_wait_entry_frame')==1)
check('exact_serialized_frame_depth_retained',lambda:all(x['frame']==frames[x['frame_index']]for x in r['matches']) and [x['frame_index']for x in r['matches']]==[0,1,2,3])
check('nested_compiler_family_frame',lambda:labels(['Microsoft.CodeAnalysis.CSharp.MethodCompiler+<>c__DisplayClass1.<CompileNamedTypeAsync>b__0()'])==['roslyn_method_compiler_frame'])
check('compiler_family_spoof_is_other_codeanalysis',lambda:labels(['Microsoft.CodeAnalysis.CSharp.MethodCompilerSpoof.Run()'])==['other_codeanalysis_frame'])
check('codeanalysis_namespace_spoof_not_recognized',lambda:labels(['Microsoft.CodeAnalysisSpoof.CSharp.MethodCompiler.Run()'])==['other_frame_context'])
check('matching_name_inside_parameter_not_frame_match',lambda:labels(['Other.Run(System.Threading.WaitHandle.WaitOne())'])==['other_frame_context'])
check('empty_stack_unresolved_not_work_progress',lambda:labels([])==['unresolved_context'])
check('unrecognized_nonempty_stack_is_other_context',lambda:labels(['Other.Run()'])==['other_frame_context'])
for frames_bad in [None,'System.Threading.Monitor.Enter()', [None], [1]]:
 check('malformed_frame_serialization_'+repr(frames_bad),lambda frames_bad=frames_bad:raises(lambda:tool.classify_frames(frames_bad)))
for method in ['System.Threading.Tasks.Task.InternalWait','System.Threading.Tasks.Task.SpinThenBlockingWait','System.Runtime.CompilerServices.TaskAwaiter.GetResult','System.Threading.ManualResetEventSlim.Wait','System.Threading.Monitor.TryEnter','System.Threading.SemaphoreSlim.WaitAsync','System.Threading.ReaderWriterLockSlim.TryEnterWriteLock','System.Threading.Thread.Join','System.Threading.Thread.Sleep']:
 check('named_wait_entry_'+method,lambda method=method:labels([method+'()'])==['managed_wait_entry_frame'])
for method in ['System.Threading.Monitor.IsEntered','System.Threading.Tasks.Task.WaitingFoo','System.Threading.WaitHandleSpoof.WaitOne','System.Threading.ManualResetEventSlim.WaitFoo','System.Threading.Thread.Sleepwalk']:
 check('wait_token_spoof_'+method,lambda method=method:labels([method+'()'])==['other_frame_context'])
for method in ['System.Runtime.CompilerServices.RuntimeHelpers.PrepareMethod','System.Reflection.Assembly.LoadFrom','System.Runtime.Loader.AssemblyLoadContext.LoadFromStream','System.Reflection.Emit.AssemblyBuilder.DefineDynamicAssembly']:
 check('named_preparation_entry_'+method,lambda method=method:labels([method+'()'])==['runtime_preparation_entry_frame'])
for method in ['System.Runtime.CompilerServices.RuntimeHelpers.GetObjectValue','System.Reflection.Assembly.GetName','System.Reflection.Assembly.LoadFromSpoof']:
 check('preparation_token_spoof_'+method,lambda method=method:labels([method+'()'])==['other_frame_context'])
check('explicit_GC_request_entry',lambda:labels(['System.GC.Collect()','System.GC.WaitForPendingFinalizers()'])==['explicit_gc_request_entry_frame'])
check('GC_other_method_not_suspension_inference',lambda:labels(['System.GC.GetGeneration()'])==['other_frame_context'])
check('generic_awaiter_balanced_argument',lambda:labels(['System.Runtime.CompilerServices.TaskAwaiter`1[System.Object].GetResult()'])==['managed_wait_entry_frame'])
check('generic_awaiter_nested_balanced_argument',lambda:labels(['System.Runtime.CompilerServices.TaskAwaiter`1[System.Collections.Generic.List`1[System.Object]].GetResult()'])==['managed_wait_entry_frame'])
for frame in ['System.Runtime.CompilerServices.TaskAwaiter`1[].GetResult()','System.Runtime.CompilerServices.TaskAwaiter`1[A].Spoof[B].GetResult()','System.Runtime.CompilerServices.TaskAwaiterSpoof`1[A].GetResult()','System.Runtime.CompilerServices.TaskAwaiter`1[A]].GetResult()','System.Runtime.CompilerServices.TaskAwaiter`1[A.GetResult()']:
 check('generic_awaiter_spoof_'+frame,lambda frame=frame:labels([frame])==['other_frame_context'])
point=dict(process_id=77,native_tid=200,time_msec=150)
query=dict(process_id=77,execution_native_tid=200,execution_start_ms=100,execution_end_ms=200,wait_begin_ms=120,wait_end_ms=180)
check('point_strict_global_intersection',lambda:tool.point_in_query(point,query)is True)
for t in [100,119,120,180,181,200]:
 p={**point,'time_msec':t};check('global_edge_or_outside_unassigned_'+str(t),lambda p=p:not tool.point_in_query(p,query))
row_query={**query,'emit_window_ms_exact_fraction':['100','130','170','200']}
check('point_strict_row_core',lambda:tool.point_in_query(point,row_query)is True)
for t in [129,130,170,171]:
 p={**point,'time_msec':t};check('row_core_edge_or_outside_unassigned_'+str(t),lambda p=p:not tool.point_in_query(p,row_query))
for window in [['100','180','150','230'],['100','190','110','200']]:
 q={**query,'emit_window_ms_exact_fraction':window};check('empty_inverted_guaranteed_core_unknown_'+repr(window),lambda q=q:not tool.point_in_query(point,q))
for window in [['100','250','150','230'],['100','110','90','200'],['-1','130','170','200'],[100,130,170,200],['100','130','170']]:
 q={**query,'emit_window_ms_exact_fraction':window};check('malformed_uncertainty_edges_rejected_'+repr(window),lambda q=q:raises(lambda:tool.point_in_query(point,q)))
for field,bad in [('process_id',True),('native_tid',True),('native_tid',0),('time_msec',True),('time_msec',-1),('time_msec',float('nan'))]:
 p={**point,field:bad};check('malformed_point_'+field+'_'+repr(bad),lambda p=p:raises(lambda:tool.point_in_query(p,query)))
for field,bad in [('process_id',True),('execution_native_tid',False),('execution_start_ms',True),('wait_begin_ms',-1),('execution_end_ms',99),('wait_end_ms',119)]:
 q={**query,field:bad};check('malformed_query_'+field+'_'+repr(bad),lambda q=q:raises(lambda:tool.point_in_query(point,q)))
check('foreign_process_point_not_promoted',lambda:not tool.point_in_query({**point,'process_id':88},query))
check('foreign_thread_point_not_promoted',lambda:not tool.point_in_query({**point,'native_tid':201},query))
check('missing_execution_keeps_unknown',lambda:not tool.point_in_query(point,{'process_id':77,'execution_native_tid':None}))
check('disjoint_wait_execution_keeps_unassigned',lambda:not tool.point_in_query(point,{**query,'execution_end_ms':110}))
check('zero_width_execution_keeps_unassigned',lambda:not tool.point_in_query(point,{**query,'execution_start_ms':150,'execution_end_ms':150}))
index=tool.IntervalIndex({200:[(Fraction(0),Fraction(20),1),(Fraction(5),Fraction(10),2)]})
check('interval_index_preserves_nested_all_candidates',lambda:index.candidates(200,7)==[1,2])
check('interval_index_retains_equal_edge_candidates',lambda:index.candidates(200,0)==[1] and index.candidates(200,20)==[1])
check('interval_index_outside_returns_none',lambda:index.candidates(200,21)==[])
for value in [{True:[(0,20,1)]},{200:[(20,0,1)]},{200:[(-1,20,1)]},{200:[(False,20,1)]},{200:[(0,20,True)]},{200:[(0,20,1),(1,5,1)]},{200:[[0,20,1]]}]:
 check('malformed_interval_index_'+repr(value),lambda value=value:raises(lambda:tool.IntervalIndex(value)))
for tid,t in [(True,1),(200,-1),(200,True)]:
 check('malformed_index_query_'+repr((tid,t)),lambda tid=tid,t=t:raises(lambda:index.candidates(tid,t)))
def state(task=1,start=100,end=200,tid=200,pid=77,status='complete_observed_lifetime'):
 return dict(task_id=task,process_id=pid,status=status,execution_native_tid=tid,start={'event':{'timeMsec':start}},complete={'event':{'timeMsec':end}})
states=[state(),state(task=2,start=140,end=160)]
check('all_containing_execution_IDs_not_ownership_choice',lambda:tool.execution_candidates(200,150,states,pid=77)==[1,2])
check('equal_inner_execution_edge_candidate_retained',lambda:tool.execution_candidates(200,140,states,pid=77)==[1,2])
check('unaccepted_execution_not_promoted',lambda:tool.execution_candidates(200,150,[state(status='rejected_poisoned_identity')],pid=77)==[])
check('explicit_foreign_process_execution_excluded',lambda:tool.execution_candidates(200,150,states+[state(task=3,pid=88)],pid=77)==[1,2])
check('mixed_process_candidates_need_scope',lambda:raises(lambda:tool.execution_candidates(200,150,states+[state(task=3,pid=88)])))
check('duplicate_task_candidate_identity_rejected',lambda:raises(lambda:tool.execution_candidates(200,150,[state(),state()],pid=77)))
check('reversed_execution_candidate_clock_rejected',lambda:raises(lambda:tool.execution_candidates(200,150,[state(start=200,end=100)],pid=77)))
points={1:{'labels':['managed_wait_entry_frame','roslyn_method_compiler_frame']},2:{'labels':['other_frame_context']}}
queries=[{'strict_point_indices':[1,2]},{'strict_point_indices':[1]},{'strict_point_indices':[]}];r=tool.summarize(queries,points)
check('point_associations_and_unique_points_separate',lambda:r['point_query_associations']==3 and r['distinct_point_indices']==2 and r['repeated_point_query_associations']==1)
check('multilabel_association_counts_not_exclusive',lambda:r['label_point_associations']=={'managed_wait_entry_frame':2,'roslyn_method_compiler_frame':2,'other_frame_context':1})
check('distinct_multilabel_points_not_added_as_time',lambda:r['distinct_points_by_label']=={'managed_wait_entry_frame':1,'roslyn_method_compiler_frame':1,'other_frame_context':1} and r['nonexclusive_labels']is True)
check('no_sample_query_unknown_not_zero_work',lambda:r['queries_without_strict_points_unknown']==1 and r['queries_with_strict_points']==2)
report={'status':'passed'if all(c['status']=='passed'for c in checks)else'failed','checks':len(checks),'failed':sum(c['status']!='passed'for c in checks),'results':checks,'worker_context_source_sha256':hashlib.sha256(Path(tool.__file__).read_bytes()).hexdigest(),'fixture_source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'limits':['Pure classifier/scope/dedup fixtures only, no CPU/blocking/progress/native-lifetime or causal proof.']}
with a.output.open('x',encoding='utf-8',newline='\n')as f:f.write(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items()if k not in ['results','limits']}));raise SystemExit(0 if not report['failed']else 1)
