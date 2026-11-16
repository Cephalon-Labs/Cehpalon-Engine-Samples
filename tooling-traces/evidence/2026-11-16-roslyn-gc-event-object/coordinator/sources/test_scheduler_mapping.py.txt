"""ADR0028 portable byte/ABI/ring/mapping guards; no actor or perf calls."""
from copy import deepcopy
import argparse,hashlib,json,struct,sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import collect_scheduler_mapping as tool

FORMAT=b"name: sys_enter_gettid\nID: 208\nformat:\n field:unsigned short common_type; offset:0; size:2; signed:0;\n field:unsigned char common_flags; offset:2; size:1; signed:0;\n field:unsigned char common_preempt_count; offset:3; size:1; signed:0;\n field:int common_pid; offset:4; size:4; signed:1;\n field:int __syscall_nr; offset:8; size:4; signed:1;\n"
def sample(pid=700,tid=700,stamp=150,cpu=1,common=900,nr=186,kind=9,size=56,rawsize=20,padding=bytes(8),event=208):
 return struct.pack('<IHHIIQIII',kind,1,size,pid,tid,stamp,cpu,0,rawsize)+struct.pack('<HBBii',event,0,0,common,nr)+padding

def run():
 checks=[]
 def check(name,fn):
  try:assert fn();checks.append(dict(name=name,status='passed'))
  except Exception as e:checks.append(dict(name=name,status='failed',error=repr(e)))
 def rejected(fn):
  try:fn()
  except (ValueError,TypeError,KeyError,struct.error,OverflowError):return True
  return False
 raw=sample();decoded=tool.decode_records(raw,208);counts=tool.counters(struct.pack('<QQQQQ',1,100,99,77,0));ready=dict(pid=700,tid=700,prearm_gettid_calls=1);result=dict(gettid_return=700,armed_gettid_calls=1,before_monotonic_ns=100,after_monotonic_ns=200)
 check('specific_zeroarg_event_exact_layout',lambda:tool.parse_syscall_format(FORMAT)['event_id']==208)
 for old,new in [(b'ID: 208',b'ID: 0'),(b'name: sys_enter_gettid',b'name: sys_enter'),(b'offset:8',b'offset:16'),(b'int __syscall_nr',b'long __syscall_nr'),(b'size:4; signed:1;',b'size:8; signed:1;'),(b'common_pid',b'other_pid')]:
  check('format_drift_'+repr(old),lambda old=old,new=new:rejected(lambda:tool.parse_syscall_format(FORMAT.replace(old,new))))
 check('no_argument_register_metadata_allowed',lambda:rejected(lambda:tool.parse_syscall_format(FORMAT+b' field:unsigned long arg0; offset:16; size:8; signed:0;\n')))
 check('record_size_56_raw20',lambda:len(raw)==56 and decoded[0]['record_size']==56 and len(bytes.fromhex(decoded[0]['raw_payload_hex']))==20)
 check('global_vs_local_ids_kept_separate',lambda:decoded[0]['global_common_pid']==900 and decoded[0]['local_tid']==700)
 check('padding_retained',lambda:decoded[0]['kernel_padding_hex']=='00'*8)
 for args in [dict(kind=2),dict(kind=5),dict(kind=6),dict(kind=13),dict(kind=99),dict(size=48),dict(size=55),dict(size=64),dict(rawsize=12),dict(rawsize=16),dict(rawsize=24),dict(common=0),dict(common=-1),dict(nr=39),dict(pid=0),dict(tid=0),dict(pid=0xffffffff),dict(event=209),dict(padding=b'x'*8)]:
  check('reject_record_'+repr(args),lambda args=args:rejected(lambda:tool.decode_records(sample(**args),208)))
 for amount in [1,4,7,8,35,40,55]:check('partial_record_rejected_'+str(amount),lambda amount=amount:rejected(lambda:tool.decode_records(raw[:amount],208)))
 check('unexplained_trailing_rejected',lambda:rejected(lambda:tool.decode_records(raw+bytes(8),208)))
 check('missing_records_not_fabricated',lambda:tool.decode_records(b'',208)==[])
 for event in [True,False,0,-1,65536,'208']:check('invalid_eventID_'+repr(event),lambda event=event:rejected(lambda:tool.decode_records(raw,event)))
 data=bytearray(tool.PAGE);start=tool.PAGE-6;data[start:]=raw[:6];data[:50]=raw[6:]
 check('forward_wrap_copy_exact',lambda:tool.forward_bytes(bytes(data),start+56,start)==raw)
 check('nonwrapped_copy_exact',lambda:tool.forward_bytes(raw+bytes(tool.PAGE-56),56,0)==raw)
 check('empty_forward_ring_remains_empty',lambda:tool.forward_bytes(bytes(data),start,start)==b'')
 for head,tail in [(0,1),(4097,0),(-1,0),(True,0),(1,False),(1<<64,(1<<64)-1),(0,-1)]:
  check('bad_head_tail_'+repr((head,tail)),lambda head=head,tail=tail:rejected(lambda:tool.forward_bytes(bytes(data),head,tail)))
 check('whole_page_ring_valid',lambda:len(tool.forward_bytes(bytes(data),tool.PAGE,0))==tool.PAGE)
 check('wrong_page_size_rejected',lambda:rejected(lambda:tool.forward_bytes(bytes(8192),0,0)))
 check('read_format23_ungrouped',lambda:counts==dict(value=1,time_enabled=100,time_running=99,perf_event_id=77,lost=0))
 check('perfID_is_not_tracepoint_ID',lambda:counts['perf_event_id']!=208)
 for length in [0,8,24,32,39,41,48]:check('short_or_extra_read_'+str(length),lambda length=length:rejected(lambda:tool.counters(bytes(length))))
 check('zero_perfID_rejected',lambda:rejected(lambda:tool.counters(struct.pack('<QQQQQ',1,2,1,0,0))))
 check('running_above_enabled_rejected',lambda:rejected(lambda:tool.counters(struct.pack('<QQQQQ',1,2,3,4,0))))
 check('one_sample_mapping_positive',lambda:tool.validate_mapping(decoded,counts,ready,result,[0,1])['observed_global_tid']==900)
 for items in [[],decoded*2]:check('missing_or_extra_mapping_samples_'+str(len(items)),lambda items=items:rejected(lambda:tool.validate_mapping(items,counts,ready,result,[0,1])))
 for key,value in [('value',0),('value',2),('value',True),('lost',1),('lost',False),('perf_event_id',0),('time_running',101)]:
  c=deepcopy(counts);c[key]=value;check('bad_mapping_counter_'+key+repr(value),lambda c=c:rejected(lambda:tool.validate_mapping(decoded,c,ready,result,[0,1])))
 for key,value in [('pid',701),('tid',701),('pid',True),('prearm_gettid_calls',2),('prearm_gettid_calls',True)]:
  r=deepcopy(ready);r[key]=value;check('bad_ready_'+key+repr(value),lambda r=r:rejected(lambda:tool.validate_mapping(decoded,counts,r,result,[0,1])))
 for key,value in [('gettid_return',701),('gettid_return',True),('armed_gettid_calls',2),('armed_gettid_calls',True),('before_monotonic_ns',151),('after_monotonic_ns',149),('before_monotonic_ns',True)]:
  r=deepcopy(result);r[key]=value;check('bad_result_'+key+repr(value),lambda r=r:rejected(lambda:tool.validate_mapping(decoded,counts,ready,r,[0,1])))
 for cpus in [[],[True],[-1],[0]]:check('bad_cpu_scope_'+repr(cpus),lambda cpus=cpus:rejected(lambda:tool.validate_mapping(decoded,counts,ready,result,cpus)))
 check('attrs_reuse_exact_B1',lambda:bytes(tool.perf.attributes(208))==bytes(tool.perf.PerfAttr.from_buffer_copy(bytes(tool.perf.attributes(208)))))
 check('kernel_ring_offsets_declared',lambda:(tool.HEAD,tool.TAIL,tool.DATA_OFFSET,tool.DATA_SIZE)==(1024,1032,1040,1048))
 # AtomicGate missing/hash/ELF failures must occur before CDLL and therefore before any actors/perf.
 with patch.object(tool.ctypes,'CDLL') as library:
  check('missing_library_no_load_fallback',lambda:rejected(lambda:tool.Atomics('/does-not-exist/libatomic.so.1','0'*64)) and not library.called)
 return dict(status='passed' if all(c['status']=='passed' for c in checks) else 'failed',checks=len(checks),results=checks,source_sha256=tool.sha(tool.__file__),actor_source_sha256=tool.sha(tool.actor_tool.__file__),test_source_sha256=tool.sha(__file__),scope='Portable bytes/models/mocks only; no actors/perf/native atomic calls')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',required=True);a=p.parse_args();r=run()
 with Path(a.output).open('x',encoding='utf-8',newline='\n') as f:json.dump(r,f,indent=2);f.write('\n')
 print(json.dumps(r));raise SystemExit(0 if r['status']=='passed' else 1)
