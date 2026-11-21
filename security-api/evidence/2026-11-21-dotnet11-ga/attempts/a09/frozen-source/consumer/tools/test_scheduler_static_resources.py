"""Pure pre-actor capacity guards. Never reads host limits or creates native resources."""
import argparse,copy,hashlib,json
from pathlib import Path
import collect_scheduler_static as c

def run():
    base={'errors':[],'online_cpu_count':20,'positive_mapping_bytes':20*8*65*4096,'negative_mapping_bytes':20*8*2*4096,'required_fd_capacity':180,'nofile':[10240,1048576],'memlock':[64*1024*1024,64*1024*1024]};results=[]
    mutations=[('normal',None,True),('infinite_limits',lambda s:s.update(nofile=[-1,-1],memlock=[-1,-1]),True),('missing_read',lambda s:s['errors'].append('read_failed'),False),('zero_cpu',lambda s:s.update(online_cpu_count=0),False),('too_many_cpu',lambda s:s.update(online_cpu_count=33),False),('bool_cpu',lambda s:s.update(online_cpu_count=True),False),('positive_footprint_drift',lambda s:s.update(positive_mapping_bytes=1),False),('negative_footprint_drift',lambda s:s.update(negative_mapping_bytes=1),False),('fd_insufficient',lambda s:s.update(nofile=[179,10240]),False),('fd_exact',lambda s:s.update(nofile=[180,10240]),True),('memlock_insufficient',lambda s:s.update(memlock=[s['positive_mapping_bytes']-1,64*1024*1024]),False),('memlock_exact',lambda s:s.update(memlock=[s['positive_mapping_bytes'],64*1024*1024]),True),('bool_nofile',lambda s:s.update(nofile=[True,10240]),False),('bool_memlock',lambda s:s.update(memlock=[True,64*1024*1024]),False)]
    for name,change,expected in mutations:
        s=copy.deepcopy(base)
        if change:change(s)
        try:c.validate_resources(s);observed=True
        except (ValueError,TypeError,KeyError):observed=False
        results.append({'name':name,'passed':observed is expected,'observed':observed})
    return results

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',required=True);a=p.parse_args();r=run();out={'status':'passed' if all(x['passed'] for x in r) else 'failed','checks':len(r),'results':r,'collector_sha256':c.sha(c.__file__),'test_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'actors':0,'perf_fds':0,'scope':'Pure capacity-value guards; no resource host probe/native call'}
    with Path(a.output).open('x',encoding='utf-8',newline='\n') as f:json.dump(out,f,indent=2);f.write('\n')
    print(json.dumps({k:out[k] for k in ['status','checks','collector_sha256']}));raise SystemExit(out['status']!='passed')
