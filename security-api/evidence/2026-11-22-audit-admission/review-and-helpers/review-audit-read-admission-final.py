"""Independent offline ADR0054 review. Run only after root declares all SDK lanes complete."""
from pathlib import Path
import argparse, ast, datetime, hashlib, json, re, subprocess

P=argparse.ArgumentParser()
P.add_argument('--execute-after-sdk-complete', action='store_true')
A=P.parse_args()
assert A.execute_after_sdk_complete, 'Root must explicitly confirm all SDK lanes complete before this offline audit'
B=Path('D:/Cephalon'); D=B/'Cehpalon-Engine-Docs'; E=B/'.worktrees/arh-engine'
EW=E/'.local/arh-wsl-source01'; S=B/'.worktrees/ara-consumer'; SW=B/'.worktrees/ara-wsl-consumer'
ER='5184517a92a087abe4e0091d256142b6c35a2b39'; SR='046daea25984e708f57387707d0f7d6abc986c91'
BASE='05f119e75bcc2458bee9c610e4ba64f04d4dc6d0'
DEV=S/'.local/audit-read-admission-windows-dev01'; FREEZE=S/'.local/audit-read-admission-windows-dev01-source'
DECL=D/'.local/audit-read-admission-declaration01'; DRIVER=E/'.local/ara-final-driver01'
DECL2=D/'.local/audit-read-admission-declaration02'
SERVICE='e3a87d11187d0b7e958a7f90c86dfca56bca8bb880e8be1f06499d312b21ece4'
SECURITY='0534d97c0deba2f33744091b828da6a8a4e375d46c44ef2ca938f2088f148489'
OUT=D/'.local/audit-read-admission-independent-review.json'
EV=D/'internal/evidence/audit-read-admission/independent-review.json'

def read(p): return json.loads(p.read_bytes())
def sha(data): return hashlib.sha256(data).hexdigest()
def filehash(p): return sha(p.read_bytes())
def git(root,*args): return subprocess.check_output(['git','-C',str(root),*args])
def canon(mapping, security=False):
    result={}
    for rawkey,value in mapping.items():
        key=rawkey.replace('\\','/')
        if security and key.startswith('consumer/'):
            rel=key.split('/',1)[1]
            if '/' not in rel and rel not in ('global.json','NuGet.Config'):key='consumer/security-api/'+rel
        if security and key.startswith('engine/Cehpalon.'):
            key='engine/src/'+key.split('/',1)[1]
        assert key not in result
        result[key]=value
    assert len(result)==len(mapping) and all(not k.startswith('/') and '..' not in k.split('/') for k in result)
    return result
def source_path(key,engine,consumer):
    prefix,rel=key.split('/',1); assert prefix in ('engine','consumer')
    return (engine if prefix=='engine' else consumer)/rel
def batch_blobs(root, revision, keys):
    """Read exact committed blobs in one bounded Git operation; avoid per-input subprocesses."""
    keys=list(keys)
    payload=''.join(revision+':'+k+'\n' for k in keys).encode()
    raw=subprocess.check_output(['git','-C',str(root),'cat-file','--batch'], input=payload)
    result={};offset=0
    for key in keys:
        end=raw.index(b'\n',offset); header=raw[offset:end].decode().split();assert len(header)==3 and header[1]=='blob'
        size=int(header[2]);start=end+1;data=raw[start:start+size]
        assert len(data)==size and raw[start+size:start+size+1]==b'\n'
        result[key]={'bytes':data,'git_blob':header[0]};offset=start+size+1
    assert offset==len(raw)
    return result
def passed_checks(tests, expected):
    assert tests['failed']==0 and tests['passed']==expected
    assert len(tests['checks'])==expected and all(c['passed'] is True for c in tests['checks'])
def build_proof(path):
    raw=(path/'build.txt').read_bytes();text=raw.decode('utf-8-sig')
    assert 'Build succeeded.' in text and re.search(r'\b0 Warning\(s\)',text) and re.search(r'\b0 Error\(s\)',text)
    return {'build_sha256':sha(raw),'Release_warnings':0,'Release_errors':0}

# Fail cheaply before hashing source if the owner has not actually completed every declared lane.
locations=[('security','Windows',S/'.local/ara-security-windows-final01',E,S),
 ('postgres','Windows',DEV,E,S),
 ('security','WSL',SW/'.local/ara-security-wsl-final01',EW,SW),
 ('postgres','WSL',SW/'.local/ara-postgres-wsl-final01',EW,SW)]
driver=read(DRIVER/'manifest.json');assert driver['status']=='passed'
dev=read(DEV/'manifest.json');assert dev['status']=='passed'
manifests={(kind,host):read(path/'manifest.json') for kind,host,path,_,_ in locations}
assert all(m['status']=='passed' for m in manifests.values())
assert not OUT.exists() and not EV.exists(), 'Retain previous independent audit receipt; choose a new declared attempt if correction is needed'

hostreview=read(D/'.local/audit-read-admission-host-review.json')
consumerreview=read(D/'.local/audit-read-admission-consumer-review.json')
assert hostreview['status']=='passed_source_review_only' and consumerreview['status']=='passed_source_review_only'
assert consumerreview['consumer_revision']==SR and not hostreview['findings'] and not consumerreview['findings']
assert git(S,'diff','--name-only',BASE,SR).decode().splitlines()==list(consumerreview['source_inputs'])
for name,info in consumerreview['source_inputs'].items():
    assert filehash(S/name)==info['sha256']
ast.parse((S/'tools/verify_audit_outbox.py').read_text(encoding='utf-8'))

freeze=read(FREEZE/'manifest.json');frozen=canon(freeze['source_sha256'])
assert freeze['status']=='frozen_before_sdk' and len(frozen)==freeze['source_count']==112
assert freeze['consumer_head']==SR and freeze['engine_head']==ER
assert len(freeze['declaration_sha256'])==freeze['declaration_count']==4
declarations=[]
for rel,digest in freeze['declaration_sha256'].items():
    assert filehash(FREEZE/'declaration'/rel)==digest and filehash(DECL/rel)==digest
    if rel!='manifest.json':assert filehash(D/rel)==digest
    declarations.append({'file':rel,'sha256':digest,'freeze_and_declared_bytes_equal':True})
schedule=read(DECL2/'manifest.json')
assert schedule['status']=='frozen_while_first_dev_pending_before_result'
assert not schedule['source_changed'] and schedule['original_declaration01_retained']
assert schedule['unique_final_sdk_executions']==4 and len(schedule['files'])==1
for rel,digest in schedule['files'].items():
    assert filehash(DECL2/rel)==digest and filehash(D/rel)==digest
scheduling_declaration={'manifest_sha256':filehash(DECL2/'manifest.json'),
 'declaration_files':2,'declared_while_first_result_pending':True,
 'same_development_and_Windows_provider_execution_counted_once':True,'manifest':schedule}
for key,digest in frozen.items():
    assert filehash(FREEZE/key)==digest and filehash(source_path(key,E,S))==digest,key

enginekeys=[k.split('/',1)[1] for k in frozen if k.startswith('engine/')]
consumerkeys=[k.split('/',1)[1] for k in frozen if k.startswith('consumer/')]
eblobs=batch_blobs(B/'Cehpalon-Engine',ER,enginekeys)
sblobs=batch_blobs(B/'Cehpalon-Engine-Samples',SR,consumerkeys)
committed={}
for key,digest in frozen.items():
    prefix,rel=key.split('/',1);data=(eblobs if prefix=='engine' else sblobs)[rel]
    assert sha(data['bytes'])==digest,key
    committed[key]={'sha256':digest,'git_blob':data['git_blob'],'revision':ER if prefix=='engine' else SR}

oldpg=read(B/'.worktrees/arh-consumer/.local/arh-postgres-windows-final01/tests.json')
oldsec=read(B/'.worktrees/arh-consumer/.local/arh-security-windows-final01/tests.json')
assert oldpg['passed']==305 and oldsec['passed']==651
oldrestart=[read(B/'.worktrees/arh-consumer/.local/arh-postgres-windows-final01'/name) for name in ('restart-write.json','restart-read.json')]
expected_groups={'prior_outbox':34,'status':23,'relay_budget':24,'drain':24,'total_drain':24,'lookup':24,
 'resource_history':32,'indexed_storage':32,'read_budget':24,'receipt_transport':28,'resource_transport':36,'admission':24}
expected_obs={'relay_budget':2,'drain':6,'total_drain':13,'lookup':15,'resource_history':22,'indexed_storage':16,
 'read_budget':24,'receipt_transport':28,'resource_transport':36,'admission':24}
def postgres_proof(path,manifest):
    tests=read(path/'tests.json');passed_checks(tests,329)
    assert tests['checks'][:305]==oldpg['checks']
    assert tests['settings']==oldpg['settings']
    for group,count in expected_groups.items():
        assert tests[group+'_passed']==count and tests[group+'_failed']==0
    for group,count in expected_obs.items():
        assert len(tests[group+'_observations'])==count and len(manifest[group+'_observations'])==count
        assert manifest[group+'_observations']==tests[group+'_observations']
    restarts=[read(path/name) for name in ('restart-write.json','restart-read.json')]
    for i,r in enumerate(restarts):
        passed_checks(r,i+1);assert r['checks']==oldrestart[i]['checks']
    assert manifest['passed']==329 and manifest['restart_passed']==3 and manifest['total_passed']==332
    assert manifest['prior_resource_transport_total_passed']==308 and manifest['source_unchanged'] is True
    assert manifest['service_registry_sha256']==SERVICE and manifest['relay_registry_sha256']==SERVICE
    assert manifest['security_registry_sha256']==SECURITY
    assert filehash(path/'generated-relay.g.cs.txt')==SERVICE
    emitted_security=list((path/'artifacts/obj/SecurityApi.Consumer').rglob('OperationRegistrations.g.cs'))
    assert len(emitted_security)==1 and filehash(emitted_security[0])==SECURITY
    ready=read(path/'owned-server-readiness.json');assert ready[-1]['exit_code']==0
    assert 'PostgreSQL audit outbox: 329/329' in (path/'run.txt').read_text(encoding='utf-8')
    return {'main_passed':329,'restart_passed':3,'total_passed':332,'failed':0,
      'old305_main_prefix_exact':True,'old308_provider_total_preserved':True,'new_checks':24,
      'new_observations':tests['admission_observations'],'settings_equal_baseline':True,
      'tests_sha256':filehash(path/'tests.json'),'restart_checks_unchanged':True,**build_proof(path)}

# The first already-committed development execution is also the Windows provider final, once only.
assert dev['engine_revision']==ER and dev['consumer_revision']==SR and not dev['engine_dirty'] and not dev['consumer_source_dirty']
devmap=canon(dev['source_sha256']);assert len(devmap)==110 and all(frozen[k]==v for k,v in devmap.items())
development=postgres_proof(DEV,dev)
for key,digest in devmap.items():assert filehash(DEV/'frozen-source'/key)==digest,key
development.update(status='passed',attempt='audit-read-admission-windows-dev01',manifest_sha256=filehash(DEV/'manifest.json'),
 source_count=110,freezer_count=112,declarations=4,all_current_frozen_committed_equal=True,
 also_windows_provider_final_same_single_execution=True)

lanes=[];maps={};finalunion={}
for kind,host,path,engine,consumer in locations:
    m=manifests[kind,host]
    assert m['engine_revision']==ER and m['consumer_revision']==SR and not m['engine_dirty'] and not m['consumer_source_dirty']
    assert m['sdk']=='11.0.100'
    mapping=canon(m['source_sha256'],security=kind=='security');assert len(mapping)==(85 if kind=='security' else 110)
    for key,digest in mapping.items():
        assert frozen[key]==digest and filehash(source_path(key,engine,consumer))==digest,key
        if kind=='postgres':assert filehash(path/'frozen-source'/key)==digest,key
        if key in finalunion:assert finalunion[key]==digest
        finalunion[key]=digest
    maps[kind,host]=mapping
    row={'kind':kind,'host':host,'path':str(path),'manifest_sha256':filehash(path/'manifest.json'),
      'source_count':len(mapping),'current_and_committed_blobs_equal':True,
      'provider_per_lane_frozen_source':kind=='postgres',
      'same_single_development_execution':kind=='postgres' and host=='Windows'}
    if kind=='security':
        t=read(path/'tests.json');passed_checks(t,651)
        assert t['checks']==oldsec['checks'] and m['passed']==651 and m['failed']==0
        assert m['registry_sha256']==SECURITY and m['tests_sha256']==filehash(path/'tests.json')
        assert filehash(path/'generated.g.cs.txt')==SECURITY
        row.update(passed=651,failed=0,old651_names_order_results_exact=True,
                   tests_sha256=filehash(path/'tests.json'),**build_proof(path))
    else:row.update(postgres_proof(path,m))
    lanes.append(row)
assert maps['security','Windows']==maps['security','WSL']
assert maps['postgres','Windows']==maps['postgres','WSL']
assert len(finalunion)==111 and set(frozen)-set(finalunion)=={'engine/src/Cehpalon.Engine.CodeGeneration/NuGet.Config'}
assert lanes[1]['new_observations']==lanes[3]['new_observations']==development['new_observations']

assert driver['engine_revision']==ER and driver['consumer_revision']==SR
expected_phases=['engine-head','engine-state','consumer-head','consumer-state','security-windows','postgres-windows-reused-original-committed-execution',
 'wsl-consumer-init','wsl-source-eol','wsl-source-ref','wsl-source-head','wsl-source-sparse','wsl-source-detach','wsl-source-state',
 'security-wsl','postgres-wsl']
assert [p['name'] for p in driver['phases']]==expected_phases and all(p['exit']==0 for p in driver['phases'])
runner=(DRIVER/'runner.py.txt').read_bytes()
assert sha(runner)==driver['runner_sha256'] and runner==(E/'.local/run-audit-read-admission-final.py').read_bytes()
assert runner==(D/'.local/run-audit-read-admission-final.py').read_bytes()
raw_phases=[]
for name in expected_phases:
    if name=='postgres-windows-reused-original-committed-execution':
        reuse=read(DRIVER/'postgres-windows-reuse.json')
        assert reuse['status']=='passed' and reuse['actual_execution']==str(DEV)
        assert reuse['manifest_sha256']==filehash(DEV/'manifest.json') and reuse['same_committed_source']
        assert not reuse['additional_sdk_execution'] and reuse['declaration']=='audit-read-admission-declaration02'
        assert reuse['unique_functional_executions_including_original']==4
        assert driver['windows_provider_reused_execution']==reuse
        raw_phases.append({'name':name,'exit':0,'reuse_receipt_sha256':filehash(DRIVER/'postgres-windows-reuse.json'),
                          'additional_sdk_execution':False,'manifest_sha256':reuse['manifest_sha256']})
        continue
    stdout=DRIVER/(name+'.stdout.txt');stderr=DRIVER/(name+'.stderr.txt')
    assert stdout.is_file() and stderr.is_file()
    raw_phases.append({'name':name,'exit':0,'stdout_sha256':filehash(stdout),'stderr_sha256':filehash(stderr)})
assert (DRIVER/'engine-head.stdout.txt').read_text().strip()==ER
assert (DRIVER/'consumer-head.stdout.txt').read_text().strip()==SR
assert not (DRIVER/'engine-state.stdout.txt').read_bytes().strip() and not (DRIVER/'consumer-state.stdout.txt').read_bytes().strip()
assert not (DRIVER/'wsl-source-state.stdout.txt').read_bytes().strip()

preparation=[]
for path in [B/'.worktrees/ara-host/.local/audit-read-admission-worktree-preparation.json',
 S/'.local/pg-reactivation-setup01-interrupted.json',S/'.local/pg-reactivation-setup02-failure.json',S/'.local/pg-reactivation-setup03.json']:
    value=read(path);preparation.append({'path':str(path),'sha256':filehash(path),'receipt':value})
assert preparation[0]['receipt']['status']=='retained_initial_setup_failure_corrected_cwd'
assert preparation[2]['receipt']['no_sdk_executed'] is True
assert preparation[3]['receipt']['status']=='passed' and preparation[3]['receipt']['native_listener_count']==1
assert not preparation[3]['receipt']['sdk_executed'] and not preparation[3]['receipt']['helpers_relaunched']

report={'schema_version':1,'status':'passed_all_declared_review_scopes',
 'reviewed_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'scope':'ADR0054 Samples-only optional shared total/per-tenant audit-read admission; Engine518 unchanged.',
 'reviewer_actions':'Independent source/design plus bounded offline source/raw/Git blob comparisons; no SDK/fixture/container/network/host mutations.',
 'source_review':{'host_receipt_sha256':filehash(D/'.local/audit-read-admission-host-review.json'),
   'consumer_receipt_sha256':filehash(D/'.local/audit-read-admission-consumer-review.json'),
   'host_checks':hostreview['checks'],'consumer_checks':consumerreview['checks'],
   'all112_unique_inputs_match_current_frozen_and_explicit_committed_blobs':True,'source_inputs':committed,
   'final_lane_union111_plus_freezer_only_CodeGeneration_NuGetConfig':True,'declarations':declarations},
 'development_review':development,
 'final_review':{'engine_revision':ER,'consumer_revision':SR,'lanes':lanes,'cross_host_maps_equal':True,
   'driver_manifest_sha256':filehash(DRIVER/'manifest.json'),'actual_runner_sha256':sha(runner),'raw_phases':raw_phases},
 'execution_scheduling':{'unique_sdk_executions':4,
   'actual_order':['original_Windows_provider_development_and_final_once','Windows_security','WSL_security','WSL_provider'],
   'scheduling_declaration02':scheduling_declaration,
   'unchanged_passing_Windows_provider_not_reexecuted':True,'same_dev_final_manifest_hash':filehash(DEV/'manifest.json')},
 'preparation_attempts':preparation,'review_checker_preparation_attempts':consumerreview['review_preparation_attempts'],
 'final_review_checker_attempts':[read(D/'.local/audit-read-admission-independent-review-attempt01.json'),
   {'status':'passed_after_security_prefix_normalization','script_sha256':filehash(Path(__file__))}],
 'registries':{'service':SERVICE,'security':SECURITY},
 'findings':[],
 'limits':['Four unique committed-source SDK executions are actual proof; initial Windows provider execution serves both development and final roles once under pre-result scheduling declaration02. Earlier wrong-cwd/controller/cleanup-acknowledgment/checker attempts are retained preparation failures, not SDK/runtime test failures.',
 'Post-SQL holds demonstrate server completion and capacity-slot ownership, not SQL still executing.',
 'Budget covers protected dispatch/owned cleanup; authentication/DTO mapping/serialization/wire flush excluded.',
 'Engine component and hosted CI evidence remain reused baseline, not newly executed host qualification.',
 'No benchmark/throughput/fairness/distributed capacity/native Windows DB/external IdP/all-provider/production claim. M0 retained.'],
 'exclusions':['Remote publication/index-byte/privacy audit, tracking synchronization23/Project253, owned-branch cleanup, fixture stop and final main/user-file audit are root-owned separate receipts.']}
data=(json.dumps(report,indent=2)+'\n').encode()
OUT.write_bytes(data);EV.parent.mkdir(parents=True,exist_ok=True);EV.write_bytes(data)
print(json.dumps({'status':report['status'],'source_union':112,'final_union':111,'final_lanes':4,'unique_sdk_executions':4,'phase_count':15,
 'development_total':332,'security_each':651,'provider_each':332,'sha256':sha(data),'receipt':str(OUT)}))
