"""ADR0029 pure recorded-state conformance; no native calls, durations or cause inference."""
from itertools import groupby

EVENTS=('sched_switch','sched_waking','sched_wakeup','sched_wakeup_new','sched_migrate_task','sched_process_fork','sched_process_exit','sched_process_free')
PID_FIELDS={name:('prev_pid','next_pid') if name=='sched_switch' else ('parent_pid','child_pid') if name=='sched_process_fork' else ('pid',) for name in EVENTS}
STATES={0:('R','runnable'),1:('S','nonrunning'),2:('D','nonrunning'),4:('T','nonrunning'),8:('t','nonrunning'),16:('X','exit'),32:('Z','exit'),64:('P','nonrunning'),128:('I','nonrunning'),256:('R+','runnable')}

def integer(value):return type(value)is int and value>=0

def ref(event,row):
    return {'event':event,'cpu':row['cpu'],'record_offset':row['record_offset'],'time_ns':row['time_ns']}

def chains_for(tid,rows,wakes,low,high):
    """Consume all observed edges. Equal-time or conflicting edges invalidate pending chains."""
    edges=[]
    for r in rows:
        if not low<r['time_ns']<high:continue
        p=r['payload']
        if p['prev_pid']==tid:edges.append((r['time_ns'],'out',r))
        if p['next_pid']==tid:edges.append((r['time_ns'],'in',r))
    edges.extend((r['time_ns'],'wake',r) for r in wakes if r['payload']['pid']==tid and low<r['time_ns']<high)
    edges.sort(key=lambda e:e[0]) # Sorting never resolves equal-time order.
    stage='unknown';out=None;wake=None;complete=[];unknown=[]
    for stamp,group in groupby(edges,key=lambda e:e[0]):
        group=list(group)
        if len(group)!=1:
            unknown.append({'time_ns':stamp,'reason':'equal_time_edges_unordered','edges':len(group)});stage='unknown';out=wake=None;continue
        _,kind,row=group[0]
        if kind=='out':
            state=row['payload']['prev_state']
            if stage in ('sleep','wake','runnable'):unknown.append({'time_ns':stamp,'reason':'pending_chain_missing_switch_in'})
            if state in (1,2):stage='sleep';out=row;wake=None
            else:
                stage='runnable' if state in (0,256) else 'unknown';out=wake=None
        elif kind=='wake':
            if stage=='sleep':stage='wake';wake=row
            else:unknown.append({'time_ns':stamp,'reason':'wakeup_without_unique_observed_sleep'});stage='unknown';out=wake=None
        else:
            if stage=='wake' and out['time_ns']<wake['time_ns']<stamp:
                complete.append({'out':ref('sched_switch',out),'out_state':out['payload']['prev_state'],'wakeup':ref('sched_wakeup',wake),'in':ref('sched_switch',row)})
            elif stage=='running':unknown.append({'time_ns':stamp,'reason':'consecutive_switch_in_missing_switch_out'})
            elif stage!='runnable':unknown.append({'time_ns':stamp,'reason':'switch_in_without_complete_sleep_wakeup'})
            stage='running';out=wake=None
    if stage in ('sleep','wake'):unknown.append({'reason':'final_pending_chain_unknown'})
    return {'complete_chains':complete,'unknown_edges':unknown,'initial_state':'unknown','final_state':'unknown','scope':'Literal recorded sleep/wakeup/switch-in chains only; no duration, CPU service or wait cause'}

def analyze_case(report,decoded_by_event,global_by_local):
    """Return every gate/unknown. passed concerns exercised static observations, never all-eight readiness."""
    failures=[];result={'passed':False,'failures':failures,'active_scheduler_ready':False,'all_eight_positive_delivery_proven':False,'wakeup_new_gate':'unexercised_unknown_static_precreation','scope':'One frozen static synthetic case; no native lifetime/GC/CPU/progress/dynamic coverage qualification'}
    def check(ok,message):
        if not ok:failures.append(message)
        return ok
    try:
        check(report['case']=='positive','Positive case required')
        low,high=report['common_start_ns'],report['common_end_ns']
        if not check(integer(low) and integer(high) and low<high,'Valid common all-FD time window'):return result
        roles=report['role_local_tids'];expected={'controller','A','B','migrator','sacrificial'}
        if not check(type(roles)is dict and set(roles)==expected and len(set(roles.values()))==5 and all(type(v)is int and 0<v<=2147483647 for v in roles.values()),'Five exact local actor roles'):return result
        if not check(type(global_by_local)is dict and set(global_by_local)==set(roles.values()) and len(set(global_by_local.values()))==5 and all(type(k)is int and type(v)is int and 0<v<=2147483647 for k,v in global_by_local.items()),'One distinct global mapping for each local actor'):return result
        global_roles={k:global_by_local[v] for k,v in roles.items()};members=set(global_roles.values());sac=global_roles['sacrificial']
        check(set(decoded_by_event)==set(EVENTS),'Exact eight decoded event channels')
        events={name:[] for name in EVENTS};prefix_suffix={name:0 for name in EVENTS};previous={};references=set();ties=0;state_counts={str(k):0 for k in STATES}
        for name in EVENTS:
            for row in decoded_by_event.get(name,[]):
                if type(row['type'])is not int or row['type']!=9:check(False,'Positive non-SAMPLE/exact-type record: '+name);continue
                if not check(integer(row['time_ns']) and integer(row['cpu']) and row['cpu']<=4095 and integer(row['record_offset']),'Exact event time/CPU/offset'):continue
                reference=(name,row['cpu'],row['record_offset']);check(reference not in references,'Duplicate per-FD raw record reference');references.add(reference)
                pids=[row['payload'][k] for k in PID_FIELDS[name]]
                if not check(all(type(p)is int and 0<=p<=2147483647 for p in pids) and any(p in members for p in pids),'Decoded exact PID fields/static payload membership'):continue
                key=(name,row['cpu']);stamp=row['time_ns']
                if key in previous:
                    check(previous[key]<=stamp,'Per-FD recorded time reversal: '+name)
                    ties+=int(previous[key]==stamp)
                previous[key]=stamp
                if name=='sched_switch':
                    state=row['payload']['prev_state'];check(type(state)is int and state in STATES,'Unsupported/mixed scheduler switch state')
                    if type(state)is int and state in STATES:state_counts[str(state)]+=1
                if low<stamp<high:events[name].append(row)
                else:prefix_suffix[name]+=1
        result.update(global_roles=global_roles,common_window={'after_ns':low,'before_ns':high,'strict_interior':True},prefix_suffix_unassigned=prefix_suffix,per_fd_equal_times=ties,state_counts=state_counts,state_dictionary={str(k):{'label':v[0],'category':v[1]} for k,v in STATES.items()})
        phases=report['phases'];names=['handoff','yield','run','migrate','nonmember_fork','sacrifice']
        if not check([p['phase'] for p in phases]==names,'Exact ordered positive phases'):return result
        phase={p['phase']:p for p in phases};last=low
        for p in phases:
            start,end=p['before_monotonic_ns'],p['after_monotonic_ns']
            check(integer(start) and integer(end) and last<=start<end<high,'Ordered phase within common active window: '+p['phase']);last=end
        delivery={}
        for role,tid in global_roles.items():
            counts={'switch':sum(tid in (r['payload']['prev_pid'],r['payload']['next_pid']) for r in events['sched_switch']),'waking':sum(r['payload']['pid']==tid for r in events['sched_waking']),'wakeup':sum(r['payload']['pid']==tid for r in events['sched_wakeup'])}
            check(all(v>0 for v in counts.values()),'Observed switch/waking/wakeup for role '+role);delivery[role]=counts
        result['delivery']=delivery
        check(not events['sched_wakeup_new'],'New generation/newwake in precreated static numeric membership')
        controlled_chains={};handoff=phase['handoff']
        for role in ('A','B'):
            candidates=[w for w in handoff['workers'] if w['tid']==roles[role]]
            if not check(len(candidates)==1,'Unique handoff worker report '+role):continue
            w=candidates[0];start,end=w['before_monotonic_ns'],w['after_monotonic_ns']
            check(integer(w['tid']) and integer(start) and integer(end) and handoff['before_monotonic_ns']<=start<end<=handoff['after_monotonic_ns'],'Worker handoff marker scope '+role)
            model=chains_for(global_roles[role],events['sched_switch'],events['sched_wakeup'],start,end)
            check(bool(model['complete_chains']),'At least one complete controlled sleep/wakeup/in chain for '+role);controlled_chains[role]=model
        result['handoff_state_chains']=controlled_chains
        migration=phase['migrate'];workers=migration['workers']
        if check(len(workers)==1 and workers[0]['tid']==roles['migrator'],'One declared migrator report'):
            worker=workers[0];steps=worker['migration_steps'];allowed=report['ready']['allowed_cpus'];check(type(allowed)is list and len(allowed)>=2 and all(type(c)is int and 0<=c<=4095 for c in allowed) and allowed==sorted(set(allowed)) and len(steps)==8,'Eight steps/two exact permitted migration CPUs');step_results=[]
            worker_start,worker_end=worker['before_monotonic_ns'],worker['after_monotonic_ns']
            check(integer(worker['tid']) and integer(worker_start) and integer(worker_end) and migration['before_monotonic_ns']<=worker_start<worker_end<=migration['after_monotonic_ns'],'Migrator worker marker within controller phase')
            previous_step_end=worker_start
            for i,s in enumerate(steps):
                start,end=s['before_monotonic_ns'],s['after_monotonic_ns'];dest=allowed[i%2]
                check(type(s['index'])is int and s['index']==i and type(s['requested_cpu'])is int and s['requested_cpu']==dest and type(s['affinity_readback'])is list and len(s['affinity_readback'])==1 and type(s['affinity_readback'][0])is int and s['affinity_readback']==[dest] and integer(start) and integer(end) and previous_step_end<=start<end<=worker_end,'Exact ordered worker-scoped migration step/readback '+str(i));previous_step_end=end
                observed=[r for r in events['sched_migrate_task'] if r['payload']['pid']==global_roles['migrator'] and start<r['time_ns']<end]
                matches=[r for r in observed if r['payload']['dest_cpu']==dest and r['payload']['orig_cpu']!=dest and (i==0 or r['payload']['orig_cpu']==allowed[(i-1)%2])]
                if i>0:check(len(observed)==len(matches)==1,'One recorded migration with controlled origin/destination for step '+str(i))
                step_results.append({'index':i,'candidates':[ref('sched_migrate_task',r) for r in matches],'all_step_records':[ref('sched_migrate_task',r) for r in observed],'initial_step_may_already_match':i==0})
            result['migration_steps']=step_results
        fork=phase['nonmember_fork'];forks=events['sched_process_fork']
        check(len(forks)==1,'Exactly one parent-side controlled fork in static membership')
        fork_candidates=[r for r in forks if r['payload']['parent_pid']==global_roles['controller'] and r['payload']['child_pid']not in members and fork['before_monotonic_ns']<r['time_ns']<fork['after_monotonic_ns']]
        check(len(fork_candidates)==1 and fork_candidates[0]['payload']['child_pid']>0 and fork['child_joined']is True and fork['child_in_static_set']is False and type(fork['nonmember_local_pid'])is int and 0<fork['nonmember_local_pid']<=2147483647 and fork['nonmember_local_pid']not in roles.values(),'Controlled nonmember fork/join; child never admitted')
        check(not any(r['payload']['child_pid']in members for r in forks),'Recorded birth into already leased static generation poisons scope')
        result['nonmember_fork']={'candidates':[ref('sched_process_fork',r) for r in fork_candidates],'child_global_id':fork_candidates[0]['payload']['child_pid'] if len(fork_candidates)==1 else None,'child_admitted':False}
        sacrifice=phase['sacrifice'];tail=report['rcu_tail'];marker=sacrifice['exit_marker']['before_monotonic_ns']
        check(all(integer(tail[k]) for k in ('requested_ns','before_monotonic_ns','after_monotonic_ns','declared_end_monotonic_ns')) and tail['requested_ns']==2000000000 and tail['declared_end_monotonic_ns']==tail['before_monotonic_ns']+2000000000 and sacrifice['after_monotonic_ns']<=tail['before_monotonic_ns']<tail['declared_end_monotonic_ns']<=tail['after_monotonic_ns']<high,'Fixed two-second RCU deadline within capture; no success from observer overshoot')
        check(sacrifice['retired_local_tid']==roles['sacrificial'] and sacrifice['python_join_returned']is True and sacrifice['native_death_proven']is False,'Retirement report separates Python join/native death')
        exits=events['sched_process_exit'];frees=events['sched_process_free']
        check(len(exits)==len(frees)==1 and all(r['payload']['pid']==sac for r in exits+frees),'Exactly one exit/free candidate for sacrifice only; duplicates/reuse poison')
        if len(exits)==len(frees)==1:
            exitrow,freerow=exits[0],frees[0];te,tf=exitrow['time_ns'],freerow['time_ns']
            check(integer(marker) and sacrifice['before_monotonic_ns']<=marker<te<tf<=tail['declared_end_monotonic_ns'],'Literal exit/free ordering inside declared retirement deadline')
            finalouts=[r for r in events['sched_switch'] if r['payload']['prev_pid']==sac and r['payload']['prev_state']in (16,32) and te<r['time_ns']<tf]
            check(len(finalouts)==1,'One terminal exit-state switch-out strictly after exit and before free')
            post=[]
            for name,rows in events.items():
                for r in rows:
                    p=r['payload'];touch=(sac in (p['prev_pid'],p['next_pid'])) if name=='sched_switch' else (sac in (p['parent_pid'],p['child_pid'])) if name=='sched_process_fork' else p['pid']==sac
                    if touch and r['time_ns']>=te:
                        post.append(ref(name,r))
                        check(r['time_ns']<=tf,'Numeric membership activity after free poisons closed generation')
            absent=[o for o in report['observations'] if integer(o.get('before_monotonic_ns')) and integer(o.get('after_monotonic_ns')) and tail['after_monotonic_ns']<=o['before_monotonic_ns']<=o['after_monotonic_ns'] and type(o.get('leases'))is dict and roles['sacrificial']not in o['leases'].get('actual_local_tids',roles.values())]
            check(bool(absent),'Retained post-tail proc observation of missing retired thread')
            result['lifecycle']={'exit':ref('sched_process_exit',exitrow),'free_candidate':ref('sched_process_free',freerow),'terminal_exit_switch_candidates':[ref('sched_switch',r) for r in finalouts],'post_exit_unassigned':post,'proc_absence_observations':len(absent),'scope':'Candidate lifecycle in retained stream, not numeric-ID reservation or immutable native lifetime; post-exit matches unassigned'}
    except (KeyError,TypeError,ValueError,IndexError) as error:
        failures.append('Malformed analysis input: '+type(error).__name__+': '+str(error))
    result['passed']=not failures
    return result
