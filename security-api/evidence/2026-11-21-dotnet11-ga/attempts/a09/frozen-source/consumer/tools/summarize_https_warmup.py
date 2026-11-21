"""Summarize every declared trace case without converting unknown time into scheduler share."""
import argparse
import json
from pathlib import Path

from analyze_https_warmup import read


def summarize(report):
    result=[]
    for case in report['cases']:
        waits=case['producer_awaits'];requests=case['requests'];largest=max(waits,key=lambda r:r['window']['duration_ms'])
        longest=max(requests,key=lambda r:r['window']['duration_ms'])
        client_gc=max(requests,key=lambda r:r['window']['client']['gc_inner_overlap_ms'])
        server_gc=max(requests,key=lambda r:r['window']['server']['gc_inner_overlap_ms'])
        result.append({'name':case['name'],'passed':case['passed'],'dropped':case['dropped'],
            'producer_awaits':len(waits),'largest_producer_await':largest,
            'awaits_with_client_gc_inner':sum(w['window']['client']['gc_inner_overlap_ms']>0 for w in waits),
            'requests_with_client_gc_inner':sum(r['window']['client']['gc_inner_overlap_ms']>0 for r in requests),
            'requests_with_server_gc_inner':sum(r['window']['server']['gc_inner_overlap_ms']>0 for r in requests),
            'longest_request':longest,'largest_client_gc_request':client_gc,'largest_server_gc_request':server_gc,
            'capture_client_task_envelopes':len(case['client']['tasks']),
            'capture_server_task_envelopes':len(case['host']['tasks']),
            'maximum_clock_residual_ms':max(case['client']['maximum_clock_residual_ms'],case['host']['maximum_clock_residual_ms']),
            'reported_events_lost':case['client']['reported_lost']+case['host']['reported_lost'],
            'kernel_scheduler_coverage':False})
    return {'status':'summarized','cases':result,'qualification':False,
            'scope':'All four executions included. GC overlaps are process-specific recorded windows, not exclusive causal shares. Kernel ready/switch and timer-ready timestamps unavailable.'}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--input',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    with args.output.open('x',encoding='utf-8',newline='\n') as file:json.dump(summarize(read(args.input)),file,indent=2);file.write('\n')
