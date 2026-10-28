"""Offline decomposition of every retained main run; no workload execution/filtering."""
import collections,datetime,gzip,hashlib,json,math,statistics,time
from pathlib import Path
BASE=Path('D:/Cephalon/Cehpalon-Engine-Samples/.local/benchmark-observation-02')
OUT=Path(__file__).resolve().parent/'variance-attempt02';OUT.mkdir(exist_ok=False)
def p(values,q):return sorted(values)[max(0,math.ceil(len(values)*q)-1)]
def cv(values):return statistics.pstdev(values)/statistics.mean(values)
def summary(rows):
    total=[x[0] for x in rows];queue=[x[1] for x in rows];sent=[x[2] for x in rows]
    return {'count':len(rows),'scheduled_p50_ms':p(total,.5),'scheduled_p95_ms':p(total,.95),'scheduled_p99_ms':p(total,.99),'queue_p50_ms':p(queue,.5),'queue_p95_ms':p(queue,.95),'queue_p99_ms':p(queue,.99),'queue_max_ms':max(queue),'sent_p50_ms':p(sent,.5),'sent_p95_ms':p(sent,.95),'sent_p99_ms':p(sent,.99),'sent_max_ms':max(sent),'over_0_5_ms':sum(x>.5 for x in total),'over_1_ms':sum(x>1 for x in total)}
started=time.time();results=[]
for transport in ['http','graphql']:
 for variant in ['baseline','engine']:
  for pair in range(5):
   d=BASE/'load'/transport/f'{pair:02}-{variant}'/'driver';report=json.loads((d/'load-result.json').read_text());path=d/'measured-requests.jsonl.gz';rows=[];ops=collections.defaultdict(list);windows=collections.defaultdict(list);seconds=collections.defaultdict(list);raw=[]
   with gzip.open(path,'rt') as f:
    frequency=json.loads(next(f))['frequency']
    for line in f:
     index,op,scheduled,sent,done,status,body,error=json.loads(line)
     assert status==200 and error=='' and sent>=scheduled and done>=sent
     q=(sent-scheduled)*1000/frequency;r=(done-sent)*1000/frequency;l=q+r;row=(l,q,r)
     rows.append(row);ops[op].append(row);seconds[index//1000].append(row);windows[index//15000].append(row);raw.append((index,op,l,q,r))
   overall=summary(rows);threshold=overall['scheduled_p95_ms'];tail=[x for x in raw if x[2]>=threshold]
   a,b=report['initialMetrics'],report['finalMetrics'];metrics={k:b[k]-a[k] for k in ['totalAllocatedBytes','cpuMilliseconds','gc0','gc1','gc2']}
   metrics['bytes_per_offered']=metrics['totalAllocatedBytes']/180000;metrics['cpu_ms_per_offered']=metrics['cpuMilliseconds']/180000
   record={'transport':transport,'variant':variant,'pair':pair+1,'source_gzip_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'overall':overall,'server_metrics_delta':metrics,'tls_connection_count_all_phases':len(report['tlsConnections']),
    'tail_decomposition':{'scheduled_p95_threshold_ms':threshold,'tail_count':len(tail),'tail_queue_median_ms':p([x[3] for x in tail],.5),'tail_queue_p95_ms':p([x[3] for x in tail],.95),'tail_sent_median_ms':p([x[4] for x in tail],.5),'tail_sent_p95_ms':p([x[4] for x in tail],.95),'tail_queue_at_least_half_count':sum(x[3]>=.5*x[2] for x in tail),'operations':dict(collections.Counter(x[1] for x in tail))},
    'by_operation':{k:summary(v) for k,v in ops.items()},'windows_15_seconds':{str(k):summary(v) for k,v in windows.items()},'seconds':{str(k):summary(v) for k,v in seconds.items()}}
   results.append(record)
   print(transport,variant,pair+1,overall['scheduled_p95_ms'],overall['sent_p95_ms'],overall['queue_p95_ms'],flush=True)
all_cv=[]
for transport in ['http','graphql']:
 for variant in ['baseline','engine']:
  selected=[r for r in results if r['transport']==transport and r['variant']==variant]
  all_cv.append({'transport':transport,'variant':variant,'all_five_scheduled_p95_ms':[r['overall']['scheduled_p95_ms'] for r in selected],'scheduled_cv':cv([r['overall']['scheduled_p95_ms'] for r in selected]),'all_five_sent_p95_ms':[r['overall']['sent_p95_ms'] for r in selected],'sent_cv':cv([r['overall']['sent_p95_ms'] for r in selected]),'queue_p95_ms_all_five':[r['overall']['queue_p95_ms'] for r in selected]})
result={'observed_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'elapsed_seconds':time.time()-started,'source':str(BASE),'runs':results,'all_five_cv':all_cv,'scope':'Offline decomposition of all20 main runs; no values removed, no benchmark rerun, not causal profiling. Sent duration includes client connection/pool/TLS/network/server/client parsing and continuation work, not pure server duration.'}
(OUT/'analysis.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
print(json.dumps({'output':str(OUT),'elapsed_seconds':result['elapsed_seconds'],'all_five_cv':all_cv}),flush=True)
