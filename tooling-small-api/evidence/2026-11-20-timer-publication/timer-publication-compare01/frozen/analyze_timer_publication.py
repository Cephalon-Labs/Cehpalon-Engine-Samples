"""Conservative managed callback/publication bounds; no kernel scheduling attribution."""
import argparse
import hashlib
import json
import math
from pathlib import Path
from statistics import mean,median

from analyze_https_warmup import require,read,load_trace,fixture_case,window

KINDS={'registered':71,'arm_before':72,'arm_after':73,'callback':74,'publish_before':75,
       'publish_after':76,'resume':77,'delay_before':78,'end':80,'disposed':81}


def bounds(before,after,observation,frequency):
    require(before['Before']<=before['After']<=after['Before']<=after['After'],'Publication bracket order differs')
    require(observation['Before']<=observation['After'] and observation['Before']>=before['After'],'Observation precedes publication call')
    return {'lower_ms':max(0,observation['Before']-after['After'])*1000/frequency,
            'upper_ms':max(0,observation['After']-before['Before'])*1000/frequency,
            'races_after_point':observation['Before']<after['After']}


def duration(before,after,frequency):
    require(before['After']<=after['Before'],'Observation points reversed')
    return {'lower_ms':(after['Before']-before['After'])*1000/frequency,
            'upper_ms':(after['After']-before['Before'])*1000/frequency}


def validate_trial(trial,frequency):
    require(trial['Status']=='passed','Failed or incomplete trial')
    profile=trial['Profile'];points=trial['Points'];require(profile in [1,2,3,4],'Unknown profile')
    expected=({'delay_before','resume','end'} if profile==1 else
              {'registered','arm_before','arm_after','callback','publish_before','publish_after','resume','end'}|({'disposed'} if profile!=4 else set()))
    require(set(points)==expected,'Missing/extra point')
    for name,p in points.items():
        kind=79 if profile==1 and name=='resume' else KINDS[name]
        require(p['Kind']==kind and 0<p['Before']<=p['After'] and p['NativeTid']>0 and p['ManagedTid']>0,'Raw point identity/order differs')
    if profile==1:
        require(not trial['Accepted'] and not trial['CallbackCompleted'] and not trial['TimerDisposed'],'Direct delay created callback state')
        result={'request_to_observed_resume':duration(points['delay_before'],points['resume'],frequency),'inline_observed':False}
    else:
        require(trial['Accepted'] and trial['RegisteredIncomplete'] and trial['CallbackCompleted'],'Registration/acceptance/cleanup differs')
        require(trial['TimerDisposed']==(profile in [2,3]),'Timer lifetime differs')
        require(points['registered']['After']<=points['arm_before']['Before'],'Armed before registered')
        require(points['callback']['After']<=points['publish_before']['Before'],'Publication precedes callback point')
        require(points['callback']['NativeTid']==points['publish_before']['NativeTid']==points['publish_after']['NativeTid'],'Publisher changed native thread')
        callback=bounds(points['arm_before'],points['arm_after'],points['callback'],frequency)
        published=bounds(points['publish_before'],points['publish_after'],points['resume'],frequency)
        inline=(points['resume']['NativeTid']==points['callback']['NativeTid']
                and points['publish_before']['After']<=points['resume']['Before']
                and points['resume']['After']<=points['publish_after']['Before'])
        require(not inline or profile==3,'Asynchronous continuation observed inside publisher on callback thread')
        if profile!=4:require(points['disposed']['Before']>=points['publish_after']['After'],'Timer disposed before callback completed')
        result={'arm_or_enqueue_to_callback':callback,'publication_to_observed_resume':published,'inline_observed':inline}
    require(points['end']['Before']>=max(p['After'] for name,p in points.items() if name!='end'),'End precedes complete trial')
    return result


def stats(values):
    return {'mean':mean(values),'median':median(values),'minimum':min(values),'maximum':max(values),
            'p95_nearest_rank':sorted(values)[math.ceil(len(values)*.95)-1]}


def analyze_case(folder):
    capture=read(folder/'capture.json');raw=read(folder/'timer-probe.json')
    require(capture['status']=='captured' and raw['status']=='passed','Incomplete probe process')
    observed=raw['observed'];count=raw['countPerProfile'];require(count==(8 if raw['mode']=='conformance' else 128),'Trial count differs')
    require(capture['observed']==observed and raw['requestedTimerMilliseconds']==1,'Probe policy differs')
    require([(r['Profile'],r['Index']) for r in raw['trials']]==[(p,i) for p in range(1,5) for i in range(count)],'Trial sequence missing/duplicated')
    frequency=raw['environment']['stopwatchFrequency'];require(frequency>0,'Invalid clock frequency')
    trace=load_trace(folder,'timer-probe') if observed else None
    if trace:require(trace['pid']==raw['environment']['pid'] and trace['frequency']==frequency,'Trace/raw identity differs')
    lookup={}
    if trace:
        for m in trace['markers']:
            p=m['payload'];key=(p['phase'],p['index'],p['kind'])
            require(key not in lookup,'Duplicate trace trial identity');lookup[key]=m
        require(len(trace['markers'])==2+sum(len(t['Points']) for t in raw['trials']),'Trace/raw point cardinality differs')
    trials=[]
    for trial in raw['trials']:
        result=validate_trial(trial,frequency);points=trial['Points']
        if trace:
            for p in points.values():
                m=lookup.get((trial['Profile'],trial['Index'],p['Kind']))
                require(m is not None and m['tid']==p['NativeTid'] and m['payload']['managedTid']==p['ManagedTid'],'Trace/raw point native identity differs')
                require(p['Before']<=m['qpc']<=p['After'],'Marker outside raw outer bracket')
            if trial['Profile']==1:
                result['whole_window']=window(points['delay_before']['Before'],points['resume']['After'],trace)
            else:
                result['callback_leg_window']=window(points['arm_before']['Before'],points['callback']['After'],trace)
                if points['publish_after']['After']<=points['resume']['Before']:
                    result['guaranteed_post_publication_window']=window(points['publish_after']['After'],points['resume']['Before'],trace)
                else:result['guaranteed_post_publication_window']=None
        trials.append({'profile':trial['Profile'],'index':trial['Index'],**result})
    groups=[]
    for profile in range(1,5):
        selected=[t for t in trials if t['profile']==profile]
        group={'profile':profile,'trials':count,'inline_observed':sum(t['inline_observed'] for t in selected)}
        for metric in (['request_to_observed_resume'] if profile==1 else ['arm_or_enqueue_to_callback','publication_to_observed_resume']):
            group[metric]={bound:stats([t[metric][bound] for t in selected]) for bound in ['lower_ms','upper_ms']}
        if profile!=1:group['publication_after_point_races']=sum(t['publication_to_observed_resume']['races_after_point'] for t in selected)
        groups.append(group)
    if observed:
        require(groups[2]['inline_observed']>0,'No positive inline control observed')
    return {'observed':observed,'count_per_profile':count,'groups':groups,'trials':trials,
            'capture':({'pid':trace['pid'],'marker_count':len(trace['markers']),'gc_episodes':trace['episodes'],
                        'reported_events_lost':trace['reported_lost'],'maximum_clock_residual_ms':trace['maximum_clock_residual_ms']} if trace else None),
            'raw_sha256':hashlib.sha256((folder/'timer-probe.json').read_bytes()).hexdigest()}


def analyze(root):
    manifest=read(root/'manifest.json');require(manifest['status']=='captured','Incomplete series')
    mode=manifest['mode'];require(mode in ['preflight','compare'],'Unknown series mode')
    expected=(['positive-fixture','control','trace'] if mode=='preflight' else
              [f'{i:02d}-{"trace" if o else "control"}' for i in range(1,5) for o in ([False,True] if i%2 else [True,False])])
    require([r['name'] for r in manifest['cases']]==expected,'Series order/count differs')
    cases=[];positive=None
    for item in manifest['cases']:
        require(item['status']=='captured','Incomplete case')
        if item['name']=='positive-fixture':positive=fixture_case(root/item['name'])
        else:cases.append({'name':item['name'],**analyze_case(root/item['name'])})
    return {'status':'validated','mode':mode,'prepared_manifest_sha256':manifest['prepared_manifest_sha256'],
            'cases':cases,'positive_fixture':positive,'qualification':False,
            'analysis_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'scope':'Synthetic same-trial bounds; callback entry is managed, not native timer-ready. Publication delay includes runtime/OS/observer work. No historical-drop or kernel-scheduler attribution.'}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--input',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    result=analyze(args.input)
    with args.output.open('x',encoding='utf-8',newline='\n') as file:json.dump(result,file,indent=2);file.write('\n')
    print(json.dumps({'status':result['status'],'cases':len(result['cases']),'trials':sum(len(c['trials']) for c in result['cases'])}))
