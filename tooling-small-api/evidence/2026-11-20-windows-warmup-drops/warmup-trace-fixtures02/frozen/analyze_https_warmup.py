"""Separate recorded GC suspension and unknown/managed scheduling evidence; never infer kernel share."""
import argparse
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path
import re
from statistics import mean, median

ROOT = Path(__file__).resolve().parents[1]
MARKER = 'Cehpalon-Https-Warmup'
CLR = 'Microsoft-Windows-DotNETRuntime'


def require(value, message):
    if not value: raise ValueError(message)


def read(path):
    raw = path.read_bytes()
    return json.loads(gzip.decompress(raw) if path.suffix == '.gz' else raw)


def overlap(start, end, intervals):
    require(end >= start, 'Reversed analysis window')
    clipped = sorted((max(start, a), min(end, b)) for a, b in intervals if a <= b and a < end and b > start)
    result = 0; last = None
    for a, b in clipped:
        if a >= b: continue
        if last is None: last = [a, b]
        elif a <= last[1]: last[1] = max(last[1], b)
        else: result += last[1] - last[0]; last = [a, b]
    return result + (last[1] - last[0] if last else 0)


def gc_episodes(events):
    opened, poisoned, episodes, errors = {}, set(), [], []
    for event in events:
        if event['provider'] != CLR: continue
        name = re.sub('[^a-zA-Z0-9]', '', event['name']).lower()
        phase = next((p for p, prefix in [('start','gcsuspendeestart'),('stop','gcsuspendeestop'),
                     ('restart','gcrestarteestart'),('end','gcrestarteestop')] if name.startswith(prefix)), None)
        if phase is None: continue
        payload = event['payload']; clr = payload.get('ClrInstanceID')
        key = (event['pid'], clr)
        if clr is None:
            errors.append({'qpc':event['qpc'],'reason':'missing CLR identity'}); continue
        if phase == 'start':
            if key in opened:
                poisoned.add(key); errors.append({'qpc':event['qpc'],'reason':'ambiguous repeated start'})
            opened[key] = {'pid':event['pid'],'clr':clr,'reason':payload.get('Reason'), 'start':event['qpc']}
        elif key not in opened:
            errors.append({'qpc':event['qpc'],'reason':'phase without start'})
        else:
            item = opened[key]
            if phase in item:
                poisoned.add(key); errors.append({'qpc':event['qpc'],'reason':'duplicate phase'})
            item[phase] = event['qpc']
            if phase == 'end':
                del opened[key]
                if key in poisoned or not all(p in item for p in ['start','stop','restart','end']) or not item['start'] <= item.get('stop',0) <= item.get('restart',0) <= item['end']:
                    errors.append({'qpc':event['qpc'],'reason':'ambiguous or incomplete episode'})
                else: episodes.append(item)
    errors.extend({'qpc':item['start'],'reason':'unfinished episode'} for item in opened.values())
    return episodes, errors


def task_envelopes(events):
    queued, seen, poisoned, intervals, errors = {}, set(), set(), [], []
    for event in events:
        if event['provider'] != 'System.Threading.Tasks.TplEventSource': continue
        name = event['name'].split('/')[0].lower(); task = event['payload'].get('TaskID')
        if task is None or name not in ['taskscheduled','taskstarted']: continue
        key = (event['pid'], task)
        if name == 'taskscheduled':
            if key in seen: poisoned.add(key); errors.append({'task':task,'reason':'reused scheduled identity'})
            seen.add(key); queued[key] = event
        elif key in queued:
            start = queued.pop(key)
            if key not in poisoned and start['qpc'] <= event['qpc']:
                intervals.append({'pid':event['pid'],'task':task,'start':start['qpc'],'end':event['qpc'],
                                  'enqueue_tid':start['tid'],'start_tid':event['tid']})
        else: errors.append({'task':task,'reason':'start without schedule'})
    errors.extend({'task':key[1],'reason':'schedule without start'} for key in queued)
    return intervals, errors


def validate_trace(events, summary, receipts):
    require(summary['reportedEventsLost'] == 0 and summary['payloadReadErrors'] == 0, 'Trace loss or unreadable payload')
    require(receipts['overflow'] == receipts['late'] == 0, 'Receipt overflow or late marker')
    markers = [e for e in events if e['provider'] == MARKER]
    count = receipts['markerCount']; records = receipts['receipts']; pid = receipts['pid']; frequency = receipts['frequency']
    require(type(frequency) is int and frequency > 0 and type(pid) is int and pid > 0, 'Invalid clock/process identity')
    require(len(markers) == len(records) == count and count > 1, 'Marker/terminal count differs')
    require(sorted(e['payload']['sequence'] for e in markers) == list(range(1,count+1)), 'Duplicate or missing marker sequence')
    require([r['Sequence'] for r in records] == list(range(1,count+1)), 'Receipt sequence differs')
    require(summary['expectedPid'] == pid, 'Trace target PID differs')
    anchor = markers[0]
    maximum_clock_residual = 0
    for event in events:
        require(event['pid'] == pid, 'Cross-process event contamination')
        residual = abs((event['qpc'] - anchor['qpc']) * 1000 / frequency - (event['milliseconds'] - anchor['milliseconds']))
        maximum_clock_residual = max(maximum_clock_residual, residual)
        require(residual <= .01, 'QPC/relative clock slope differs')
    for event in markers:
        p = event['payload']; r = records[p['sequence']-1]
        require(event['pid'] == p['pid'] == r['Pid'] == pid and event['tid'] == p['nativeTid'] == r['NativeTid'], 'Marker native identity differs')
        require(r['BeforeTicks'] <= event['qpc'] <= r['AfterTicks'] and p['ticks'] == r['BeforeTicks'], 'Marker outside receipt bracket')
        require(all(p[k] == r[v] for k,v in [('kind','Kind'),('phase','Phase'),('index','Index'),('lane','Lane'),('managedTid','ManagedTid')]), 'Marker payload differs from receipt')
    ordered = sorted(markers,key=lambda e:e['payload']['sequence'])
    require(ordered[0]['payload']['kind'] == 1 and ordered[-1]['payload']['kind'] == 2, 'Capture marker lifecycle differs')
    episodes, errors = gc_episodes(events)
    begin, end = ordered[0]['qpc'], ordered[-1]['qpc']
    inside_errors = [error for error in errors if begin <= error['qpc'] <= end]
    require(not inside_errors, 'Incomplete/ambiguous suspension inside application capture')
    tasks, task_errors = task_envelopes(events)
    return {'pid':pid,'frequency':frequency,'markers':ordered,'episodes':episodes,'gc_pairing_errors':errors,
            'tasks':tasks,'task_pairing_errors':task_errors,'maximum_clock_residual_ms':maximum_clock_residual}


def load_trace(folder, role):
    directory = folder / (role+'-events')
    events = [json.loads(line) for line in (directory/'events.jsonl').read_text(encoding='utf-8').splitlines()]
    summary = read(directory/'summary.json'); receipts = read(folder/(role+'.json.receipts.json'))
    result = validate_trace(events,summary,receipts)
    result.update(event_counts=summary['eventCounts'], reported_lost=summary['reportedEventsLost'], raw_sha256=summary['traceSha256'])
    return result


def project(trace):
    return {key:value for key,value in trace.items() if key not in ['markers']}


def window(start, end, client, host=None):
    frequency = client['frequency']; total = end-start
    result = {'start':start,'end':end,'duration_ms':total*1000/frequency}
    for role, trace in [('client',client),('server',host)]:
        if trace is None: continue
        gc = [e for e in trace['episodes'] if e['reason'] in [1,6]]
        inner = overlap(start,end,[(e['stop'],e['restart']) for e in gc])
        envelope = overlap(start,end,[(e['start'],e['end']) for e in gc])
        other = overlap(start,end,[(e['start'],e['end']) for e in trace['episodes'] if e['reason'] not in [1,6]])
        tasks = [t for t in trace['tasks'] if t['start'] < end and t['end'] > start]
        result[role] = {'gc_inner_overlap_ms':inner*1000/frequency,'gc_envelope_overlap_ms':envelope*1000/frequency,
                        'outside_recorded_gc_envelopes_ms':(total-envelope)*1000/frequency,'other_suspension_envelope_overlap_ms':other*1000/frequency,
                        'overlapping_process_task_envelopes':len(tasks)}
    return result


def historical(path):
    data = read(path); phase = data['phases'][0]; rows = phase['Rows']; frequency = data['environment']['stopwatchFrequency']
    require(len(rows)==1500 and phase['Rate']==500 and phase['Name']=='warmup', 'Historical workload differs')
    require([r['Index'] for r in rows]==list(range(1500)), 'Historical offer missing')
    for i,r in enumerate(rows):
        require(r['Lane']==i%32 and r['Scheduled']==phase['Origin']+i*frequency//500, 'Historical offer identity/schedule differs')
        if r['Outcome']=='passed':
            require(r['Scheduled']<=r['Sent']<=r['Completed']<=phase['Completed'] and r['Status']==200 and r['Bytes']>0,'Historical successful request differs')
    drops=[r for r in rows if r['Outcome']=='dropped']
    require([r['Index'] for r in drops]==[1190,1191,1192,1193,1194] and sum(r['Outcome']=='passed' for r in rows)==1495,'Historical outcomes differ')
    result=[]
    for d in drops:
        require(d['Sent']==0 and d['Completed']>=d['Scheduled'],'Historical drop clock differs')
        preceding=[r for r in rows[:d['Index']] if r['Lane']==d['Lane'] and r['Sent']>0][-1]
        pending=[r['Index'] for r in rows if 0<r['Sent']<=d['Completed']<r['Completed']]
        require(preceding['Index'] in pending and len(pending)==32,'Historical pending set differs')
        result.append({'index':d['Index'],'lane':d['Lane'],'scheduled':d['Scheduled'],'recorded':d['Completed'],
                       'lateness_ms':(d['Completed']-d['Scheduled'])*1000/frequency,'predecessor':preceding,'pending_request_indexes':pending})
    require(drops[0]['Completed']>=drops[-1]['Scheduled'],'Not one overdue catch-up burst')
    return {'status':'replayed','input_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'drops':result,
            'burst_ms':(drops[-1]['Completed']-drops[0]['Completed'])*1000/frequency,
            'scheduled_span_ms':(drops[-1]['Scheduled']-drops[0]['Scheduled'])*1000/frequency,
            'runtime_gc_or_kernel_evidence_available':False}


def fixture_case(folder):
    capture=read(folder/'capture.json'); data=read(folder/'trace-fixture.json')
    require(capture['status']=='captured' and data['status']=='passed' and data['iterations']==10000 and data['checksum']==49995000,'Fixture differs')
    result={'observed':data['observed'],'loop_us':data['loopWallTicks']*1_000_000/data['environment']['stopwatchFrequency'],
            'loop_allocated_bytes':data['loopAllocatedBytes']}
    if data['observed']:
        trace=load_trace(folder,'trace-fixture')
        require(any(e['reason'] in [1,6] for e in trace['episodes']),'Missing positive GC suspension')
        require(trace['tasks'] and any('ThreadPool' in k for k in trace['event_counts']),'Missing managed scheduling positive control')
        require(sum(m['payload']['kind']==50 for m in trace['markers'])==10000,'Marker loop count differs')
        result['trace']=project(trace)
    return result


def warmup_case(folder):
    capture=read(folder/'capture.json'); data=read(folder/'client.json'); host_data=read(folder/'host.json')
    require(capture['status']=='captured','Capture not complete')
    client=load_trace(folder,'client'); host=load_trace(folder,'host')
    require(client['pid']!=host['pid'] and client['frequency']==host['frequency'],'Owned process/clock scopes differ')
    require(data['crossTenantDenials']==4 and data['prepared']==32 and len(data['tls'])==32,'Transport/tenant controls differ')
    require(len(data['phases'])==1 and data['phases'][0]['Name']=='warmup','Unexpected measured phase')
    phase=data['phases'][0]; expected=128 if capture['profile']=='conformance' else 1500
    require(len(phase['Rows'])==expected and phase['Rate']==(128 if expected==128 else 500),'Diagnostic workload differs')
    passed=sum(r['Outcome']=='passed' for r in phase['Rows']);dropped=sum(r['Outcome']=='dropped' for r in phase['Rows'])
    require(passed+dropped==expected,'Unexpected HTTP/validation error')
    count=32+passed
    require(host_data['store']=={'Factories':count,'Constructors':count,'Reads':count,'Writes':0,'Disposals':count},'Owned cleanup differs')
    require(host_data['counters']['HostDisposals']==1 and host_data['counters']['ForbiddenFactories']==0 and host_data['snapshot']['ActiveOperations']==0 and host_data['snapshot']['IsAdmissionClosed'],'Host terminal state differs')
    markers=client['markers']; lookup={}
    for event in markers:
        p=event['payload'];key=(p['kind'],p['phase'],p['index'])
        require(key not in lookup,'Duplicate application stage identity');lookup[key]=event
    server_counts=Counter((m['payload']['kind'],m['payload']['index']) for m in host['markers'] if m['payload']['phase']==1)
    requests=[];delays=[];drops=[]
    for row in phase['Rows']:
        i=row['Index'];require(i<len(phase['Rows']) and row['Lane']==i%32,'Request lane differs')
        if row['Outcome']=='dropped':
            require((21,1,i) in lookup and (20,1,i) not in lookup,'Drop decision marker differs')
            d=lookup[(21,1,i)]; preceding=[r for r in phase['Rows'][:i] if r['Lane']==row['Lane'] and r['Sent']>0][-1]
            drops.append({'index':i,'predecessor':preceding['Index'],'decision':d['qpc'],
                          'predecessor_window':window(preceding['Sent'],preceding['Completed'],client,host)})
        else:
            require(all((kind,1,i) in lookup for kind in [19,20,22,23,24,25]),'Request stage missing')
            require(server_counts[(30,i)]==server_counts[(31,i)]==1,'Server request stage missing/duplicated')
            requests.append({'index':i,'lane':row['Lane'],'window':window(row['Sent'],row['Completed'],client,host),
                             'response_content_qpc':lookup[(22,1,i)]['qpc'],'validated_qpc':lookup[(23,1,i)]['qpc'],
                             'release_before_qpc':lookup[(24,1,i)]['qpc'],'release_after_qpc':lookup[(25,1,i)]['qpc']})
    for event in markers:
        p=event['payload']
        if p['kind']==10 and p['phase']==1:
            end=lookup.get((11,1,p['index']));require(end is not None,'Producer await lacks resume')
            delays.append({'id':p['index'],'offer':p['lane'],'begin_tid':event['tid'],'resume_tid':end['tid'],
                           'window':window(event['qpc'],end['qpc'],client,host)})
    return {'status':'validated','passed':passed,'dropped':dropped,'client':project(client),'host':project(host),
            'requests':requests,'producer_awaits':delays,'drops':drops,
            'scope':'All stage windows retained. Uncovered time is unknown; process-level task envelopes lack exact request lineage. No kernel scheduler coverage.'}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--input',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();manifest=read(args.input/'manifest.json');require(manifest['status']=='captured','Incomplete capture series')
    result={'status':'validated','mode':manifest['mode'],'cases':[],'qualification':False}
    for case in manifest['cases']:
        result['cases'].append({'name':case['name'],**(fixture_case(args.input/case['name']) if manifest['mode']=='fixtures' else warmup_case(args.input/case['name']))})
    if manifest['mode']=='fixtures':
        paired=[]
        for i in range(1,5):
            group=[r for r in result['cases'] if r['name'].startswith(f'{i:02d}-')]
            a=next(r for r in group if not r['observed']);b=next(r for r in group if r['observed'])
            paired.append({'pair':i,'wall_us_difference':b['loop_us']-a['loop_us'],'allocated_bytes_difference':b['loop_allocated_bytes']-a['loop_allocated_bytes']})
        result['observer_loop_pairs']=paired
    result['analysis_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    with args.output.open('x',encoding='utf-8',newline='\n') as file:json.dump(result,file,indent=2);file.write('\n')
    print(json.dumps({'status':result['status'],'cases':len(result['cases']),'drops':[r.get('dropped') for r in result['cases']]}))


if __name__=='__main__':main()
