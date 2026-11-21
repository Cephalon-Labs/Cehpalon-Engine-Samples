"""Independent OFFLINE evidence review. Execute only after root finishes all SDK lanes.

No SDK, container, network or Git mutations. Config can override paths/revisions;
all original failed evidence remains required. Counts of source/declaration files
are derived from retained manifests rather than assumed from a previous wave.
"""
from pathlib import Path,PurePosixPath
from datetime import datetime,timezone
import argparse,hashlib,json,re,subprocess

B=Path('D:/Cephalon');D=B/'Cehpalon-Engine-Docs';E=B/'.worktrees/arh-engine';EW=E/'.local/arh-wsl-source01';S=B/'.worktrees/ahx-consumer';SW=B/'.worktrees/ahx-wsl-consumer'
ENGINE='5184517a92a087abe4e0091d256142b6c35a2b39';ORIGINAL='acba0da39f9d50204627ff75ac135d8b50af2180';SECOND='d013d61ae2cc22f2d79fefc29fd64482b4888f13';FINAL='fd7bb17ffcdcfb9f75753f509f0b3e1da883adbf'
SERVICE='e3a87d11187d0b7e958a7f90c86dfca56bca8bb880e8be1f06499d312b21ece4';SECURITY='0534d97c0deba2f33744091b828da6a8a4e375d46c44ef2ca938f2088f148489'
checks=[];blobs={};verified_sources={}
def read(path):return json.loads(Path(path).read_bytes())
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def digest(data):return hashlib.sha256(data).hexdigest()
def rel(key):
    p=PurePosixPath(key);assert not p.is_absolute() and '..' not in p.parts and ':' not in key and '\n' not in key,key
    return Path(*p.parts)
def git(root,*args):return subprocess.check_output(['git','-C',str(root),*args])
def load_blobs(root,refs):
    requested=sorted(set(refs)-{ref for base,ref in blobs if base==str(root)})
    if not requested:return
    p=subprocess.run(['git','-C',str(root),'cat-file','--batch'],input=('\n'.join(requested)+'\n').encode(),capture_output=True,check=True)
    data=p.stdout;offset=0
    for ref in requested:
        end=data.index(b'\n',offset);header=data[offset:end].split();assert len(header)==3 and header[1]==b'blob',(ref,header)
        size=int(header[2]);start=end+1;body=data[start:start+size];assert data[start+size:start+size+1]==b'\n';offset=start+size+1;blobs[(str(root),ref)]=body
    assert offset==len(data)
def source_blob(key,revision):
    prefix,tail=key.split('/',1);assert prefix in ('engine','consumer');root=E if prefix=='engine' else S;rev=ENGINE if prefix=='engine' else revision
    return root,rev+':'+rel(tail).as_posix()
def prepare_blobs(mapping,revision):
    refs={E:[],S:[]}
    for key in mapping:
        root,ref=source_blob(key,revision);refs[root].append(ref)
    for root,items in refs.items():load_blobs(root,items)
def frozen_file(root,key):
    options=[Path(root)/'frozen-source'/rel(key),Path(root)/rel(key)];found=[x for x in options if x.is_file()];assert found,('missing-frozen',str(root),key);return found[0]
def verify_sources(root,mapping,revision,engine,consumer,current=True):
    prepare_blobs(mapping,revision)
    for key,expected in mapping.items():
        assert sha(frozen_file(root,key))==expected,('frozen',str(root),key)
        prefix,tail=key.split('/',1);base=engine if prefix=='engine' else consumer
        if current:assert sha(base/rel(tail))==expected,('current',key,str(base))
        repo,ref=source_blob(key,revision);assert digest(blobs[(str(repo),ref)])==expected,('commit',key,revision)
        verified_sources[(revision,key)]=expected
def verify_declarations(root,mapping,declarations):
    for key,expected in mapping.items():
        candidates=[Path(root)/'declaration'/rel(key),Path(root)/'frozen-declarations'/rel(key)]
        assert any(x.is_file() and sha(x)==expected for x in candidates),('frozen-declaration',str(root),key)
        parts=PurePosixPath(key).parts;original=[]
        for declaration in declarations:
            declaration=Path(declaration);original.append(declaration/rel(key))
            if len(parts)>1 and (parts[0]==declaration.name or re.fullmatch(r'\d+',parts[0]) and declaration.name.endswith(parts[0])):
                original.append(declaration/Path(*parts[1:]))
        assert any(x.is_file() and sha(x)==expected for x in original),('retained-declaration',key)
def check_build(root):
    data=(Path(root)/'build.stdout.txt').read_text(encoding='utf-8');assert 'Build succeeded.' in data and re.search(r'^\s*0 Warning\(s\)\s*$',data,re.M) and re.search(r'^\s*0 Error\(s\)\s*$',data,re.M)
def check_registry(root,manifest):
    assert manifest['service_registry_sha256']==SERVICE and sha(Path(root)/'generated-service.cs.txt')==SERVICE
    assert manifest['security_registry_sha256']==SECURITY and sha(Path(root)/'generated-security.cs.txt')==SECURITY
def check_binary(root,mapping):
    assert mapping
    for name,expected in mapping.items():assert sha(Path(root)/rel(name))==expected,('binary',str(root),name)
def assert_observations(tests,phase):
    expected_offline=['contract_offline_selection','contract_offline_http_shapes','contract_offline_graphql','contract_offline_detached','contract_offline_determinism','contract_offline_publication','contract_offline_cli','contract_offline_generated_subset']
    expected_wire=[x for _ in (0,1) for x in ['contract_wire_parity','contract_wire_disabled','contract_wire_tenant_isolation','contract_wire_authority_and_capacity']]
    assert tests['passed']==8 and tests['failed']==0 and len(tests['checks'])==8 and len(tests['observations'])==8
    assert all(x['passed'] is True for x in tests['checks'])
    assert [x['phase'] for x in tests['observations']]==(expected_offline if phase=='offline' else expected_wire)
    if phase=='wire':assert [x['transport'] for x in tests['observations']]==['HTTP']*4+['GraphQL']*4

def main():
    p=argparse.ArgumentParser();p.add_argument('--execute-after-sdk-complete',action='store_true');p.add_argument('--config',type=Path);a=p.parse_args();assert a.execute_after_sdk_complete,'Root must confirm all SDK lanes have completed before audit'
    cfg=read(a.config) if a.config else {};revision=cfg.get('consumer_revision',FINAL)
    old=Path(cfg.get('original_failed_windows',S/'.local/ahx-offline-windows01'))
    driver=Path(cfg.get('driver_output',E/'.local/ahx-driver03'));driver_script=Path(cfg.get('driver_script',E/'.local/run-audit-contract-export03.py'))
    driver01=Path(cfg.get('original_driver_output',E/'.local/ahx-driver01'))
    driver02=Path(cfg.get('second_driver_output',E/'.local/ahx-driver02'))
    freezes=[(Path(cfg.get('original_source_freeze',S/'.local/audit-contract-export-source01')),ORIGINAL,False),(Path(cfg.get('second_source_freeze',S/'.local/audit-contract-export-source02')),SECOND,False),(Path(cfg.get('final_source_freeze',S/'.local/audit-contract-export-source03')),revision,True)]
    declarations=[Path(x) for x in cfg.get('declarations',[D/'.local/audit-contract-export-declaration01',D/'.local/audit-contract-export-declaration02',D/'.local/audit-contract-export-declaration03'])]
    wsl_offline=Path(cfg.get('wsl_offline',SW/'.local/ahx-offline-wsl03'));final_sw=Path(cfg.get('wsl_consumer_root',wsl_offline.parent.parent))
    phases=[('windows','offline',Path(cfg.get('windows_offline',S/'.local/ahx-offline-windows03')),E,S),('wsl','offline',wsl_offline,EW,final_sw),('windows','wire',Path(cfg.get('windows_wire',S/'.local/ahx-wire-windows03')),E,S),('wsl','wire',Path(cfg.get('wsl_wire',final_sw/'.local/ahx-wire-wsl03')),EW,final_sw)]
    # Cheap completion guards run before any broad hashing or Git-object review.
    manifests=[read(root/'manifest.json') for _,_,root,_,_ in phases];dm=read(driver/'manifest.json')
    assert dm['status']=='passed' and all(m['status']=='passed' and m['passed']==8 and m['failed']==0 for m in manifests),'SDK lanes incomplete or failed; do not audit/relabel as pass'
    assert not git(S,'status','--porcelain').strip() and git(S,'rev-parse','HEAD').decode().strip()==revision
    assert git(E,'rev-parse','HEAD').decode().strip()==ENGINE and not git(E,'status','--porcelain').strip()
    assert (final_sw/'.git/HEAD').read_text().strip()==revision
    source_receipt=read(D/'.local/audit-contract-consumer-review.json');host_receipt=read(D/'.local/audit-contract-host-review.json');correction=read(D/'.local/audit-contract-newline-correction-review.json')
    assert source_receipt['status']==host_receipt['status']=='passed_source_review_only' and source_receipt['consumer_revision']==ORIGINAL
    assert correction['status']=='passed_source_correction_review_only' and correction['exact_single_options_property_addition']
    prefix_review=read(D/'.local/audit-contract-fixture-prefix-correction-review.json');assert prefix_review['status']=='passed_source_correction_review_only' and prefix_review['exact_single_fixture_literal_change'] and prefix_review['provider_guard_byte_identical']
    file='audit-outbox/AuditReadContractExport.cs';fixture_file='audit-outbox/AuditContractChecks.cs';oldsrc=git(S,'show',ORIGINAL+':'+file);newsrc=git(S,'show',SECOND+':'+file)
    assert git(S,'diff','--name-only',ORIGINAL,SECOND).decode().splitlines()==[file] and git(S,'show',revision+':'+file)==newsrc
    needle=b'IncludeFields = true, WriteIndented = true';assert oldsrc.count(needle)==1 and newsrc==oldsrc.replace(needle,needle+b', NewLine = "\\n"',1)
    assert digest(oldsrc)==correction['before_sha256'] and digest(newsrc)==correction['after_sha256']
    before_fixture=git(S,'show',SECOND+':'+fixture_file);after_fixture=git(S,'show',revision+':'+fixture_file);fixture_needle=b'new PostgresStore(connection, "ac_" + Guid.NewGuid().ToString("N"))';fixture_replacement=b'new PostgresStore(connection, "ao_" + Guid.NewGuid().ToString("N"))'
    assert before_fixture.count(fixture_needle)==1 and after_fixture==before_fixture.replace(fixture_needle,fixture_replacement,1)
    assert git(S,'diff','--name-only',SECOND,revision).decode().splitlines()==[fixture_file] and digest(after_fixture)==prefix_review['after_sha256'] and digest(before_fixture)==prefix_review['before_sha256']
    assert git(S,'show',SECOND+':audit-outbox/PostgresStore.cs')==git(S,'show',revision+':audit-outbox/PostgresStore.cs')
    checks.append({'scope':'immutable reviewed source and corrections','original_reviewed_files':len(source_receipt['source_inputs']),'host_review_scopes':len(host_receipt['reviewed_scopes']),'consumer_review_scopes':len(source_receipt['reviewed_scopes']),'exact_source_deltas':['Shared JSON serializer NewLine explicitly LF','New test fixture schema ac_ to ao_ literal only; provider guard/assertions/verifier/limits unchanged']})
    # Historical failed attempt remains byte-for-byte tied to the original revision.
    om=read(old/'manifest.json');ot=read(old/'tests.json');assert om['status']=='failed' and om['consumer_revision']==ORIGINAL and om['passed']==ot['passed']==7 and om['failed']==ot['failed']==1
    assert len(ot['checks'])==8 and [x['name'] for x in ot['checks'] if not x['passed']]==['offline deterministic UTF8 LF payload bytes and manifest hashes']
    assert sha(old/'manifest.json')==correction['original_failed_execution']['manifest_sha256'] and sha(old/'tests.json')==correction['original_failed_execution']['tests_sha256']
    verify_sources(old,om['source_sha256'],ORIGINAL,E,S,current=False);check_build(old);check_registry(old,om);check_binary(old,om['binary_sha256'])
    for name,proof in correction['original_failed_execution']['retained_cli_artifacts'].items():assert sha(old/'contract-proof/cli-both'/name)==proof['sha256']
    olddriver=read(driver01/'manifest.json');assert olddriver['status']=='failed' and olddriver['consumer_revision']==ORIGINAL and olddriver['phases'][-1]=={'name':'offline-windows','exit':1};assert sha(driver01/'runner.py.txt')==olddriver['runner_sha256']
    checks.append({'scope':'original failed SDK attempt retained','passed':7,'failed':1,'source_inputs':len(om['source_sha256']),'build_warnings':0,'build_errors':0,'failure':'Deterministic UTF8/LF check; original JSON CRLF unchanged, SDL alreadyLF','normalized_original_raw':False})
    # Attempt02 passed both offline lanes but its fixture naming prevented ALL wire checks.
    historical02=[('windows',Path(cfg.get('second_windows_offline',S/'.local/ahx-offline-windows02')),E,S),('wsl',Path(cfg.get('second_wsl_offline',SW/'.local/ahx-offline-wsl02')),EW,SW)]
    historical02_manifests=[]
    for host,root,engine,consumer in historical02:
        m=read(root/'manifest.json');assert m['status']=='passed' and m['phase']=='offline' and m['consumer_revision']==SECOND and m['passed']==8 and m['failed']==0
        assert_observations(read(root/'tests.json'),'offline');verify_sources(root,m['source_sha256'],SECOND,engine,consumer,current=False);check_build(root);check_registry(root,m);check_binary(root,m['binary_sha256']);verify_declarations(root,m['declaration_sha256'],declarations);historical02_manifests.append(m)
        captured=next(x for x in prefix_review['retained_attempt02']['offline_passes'] if x['host']==host);assert sha(root/'manifest.json')==captured['manifest_sha256']
    oldwire=Path(cfg.get('second_failed_windows_wire',S/'.local/ahx-wire-windows02'));wm=read(oldwire/'manifest.json');wt=read(oldwire/'tests.json')
    assert wm['status']=='failed' and wm['phase']=='wire' and wm['consumer_revision']==SECOND and wm['passed']==wt['passed']==0 and wm['failed']==wt['failed']==8
    assert len(wt['checks'])==8 and wt['observations']==[] and wt['schemas']==[] and all(not x['passed'] and x['error_type']=='System.ArgumentException' and x['error']=='Owned schema identifier required.' for x in wt['checks'])
    assert sha(oldwire/'manifest.json')==prefix_review['retained_attempt02']['windows_wire']['manifest_sha256'] and sha(oldwire/'tests.json')==prefix_review['retained_attempt02']['windows_wire']['tests_sha256']
    verify_sources(oldwire,wm['source_sha256'],SECOND,E,S,current=False);check_registry(oldwire,wm)
    assert wm['build_executed'] is False and wm['exact_offline_binaries_reused'] is True and wm['binary_sha256']==historical02_manifests[0]['binary_sha256'] and wm['offline_manifest_sha256']==sha(historical02[0][1]/'manifest.json')
    d02=read(driver02/'manifest.json');assert d02['status']=='failed' and d02['consumer_revision']==SECOND and d02['phases'][-1]=={'name':'wire-windows','exit':1};assert sha(driver02/'runner.py.txt')==d02['runner_sha256']
    assert not any(x['name']=='wire-wsl' for x in d02['phases'])
    assert historical02_manifests[0]['deterministic_artifact_sha256']==historical02_manifests[1]['deterministic_artifact_sha256']
    checks.append({'scope':'attempt02 partial matrix retained','windows_offline_passed':8,'wsl_offline_passed':8,'windows_wire_passed':0,'windows_wire_failed':8,'all_wire_errors':'Owned schema identifier required before Initialize','wire_observations':0,'wire_schemas':0,'wsl_wire_not_executed':True,'historical_builds':2,'historical_wire_rebuilds':0,'old_binaries_not_substituted_into_final_candidate':True})
    maps=[];freeze_reports=[]
    for root,rev,current in freezes:
        m=read(root/'manifest.json');mapping=m['source_sha256'];verify_sources(root,mapping,rev,E,S,current=current);verify_declarations(root,m['declaration_sha256'],declarations)
        assert m['consumer_head']==rev and m['engine_head']==ENGINE and m['source_count']==len(mapping) and m['declaration_count']==len(m['declaration_sha256'])
        freeze_reports.append({'path':str(root),'revision':rev,'source_files':len(mapping),'declaration_files':len(m['declaration_sha256']),'matches_final_current':current});maps.append(mapping)
    assert set(maps[0])==set(maps[1])==set(maps[2]);assert [k for k in maps[0] if maps[0][k]!=maps[1][k]]==['consumer/'+file];assert [k for k in maps[1] if maps[1][k]!=maps[2][k]]==['consumer/'+fixture_file]
    finalmap=maps[-1];assert set(finalmap)==set(om['source_sha256'])
    checks.append({'scope':'original and corrected source/declaration freezes','freezes':freeze_reports,'source_correction_chain':['consumer/'+file,'consumer/'+fixture_file],'derived_source_count':len(finalmap)})
    for (host,phase,root,engine,consumer),m in zip(phases,manifests):
        assert m['engine_revision']==ENGINE and m['consumer_revision']==revision and m['phase']==phase and m['source_unchanged'] and m['source_sha256']==finalmap
        verify_sources(root,m['source_sha256'],revision,engine,consumer);check_registry(root,m);t=read(root/'tests.json');assert_observations(t,phase)
        assert m['observations']==t['observations'];assert m['legacy_source_preservation']['prior_provider_332_and_security_651_reused_not_rerun']
        if phase=='offline':
            assert m['build_executed'] is True;check_build(root);check_binary(root,m['binary_sha256']);verify_declarations(root,m['declaration_sha256'],declarations)
            for child in (root/'contract-proof/deterministic').iterdir():
                if child.is_file():assert b'\r' not in child.read_bytes(),('corrected-new-artifact-line-ending',host,child.name)
            assert m['deterministic_artifact_sha256']=={f.name:sha(f) for f in (root/'contract-proof/deterministic').iterdir() if f.is_file()}
            manifest=read(root/'contract-proof/deterministic/manifest.json')
            for artifact in manifest['artifacts']:
                f=root/'contract-proof/deterministic'/artifact['name'];assert sha(f)==artifact['sha256'] and f.stat().st_size==artifact['bytes']
            for index in range(5):
                assert not (root/f'contract-proof/cli-negative-{index}.stdout.txt').read_text().strip()
                rejection=read(root/f'contract-proof/cli-negative-{index}.stderr.txt');assert rejection['code']=='audit.contract_export_rejected' and rejection['status']=='failed'
                assert rejection['counters']['HandlerFactoryCalls']==rejection['counters']['DispatchCalls']==0
        else:
            offline=phases[0][2] if host=='windows' else phases[1][2];orig=manifests[0] if host=='windows' else manifests[1]
            assert m['build_executed'] is False and m['exact_offline_binaries_reused'] is True and m['offline_manifest_sha256']==sha(offline/'manifest.json')
            assert m['binary_sha256']==orig['binary_sha256'] and m['dotnet_executable']==orig['dotnet_executable'] and m['dotnet_executable_sha256']==orig['dotnet_executable_sha256'];check_binary(offline,m['binary_sha256'])
            assert (root/'run.stdout.txt').is_file() and (root/'run.stderr.txt').is_file() and not (root/'build.stdout.txt').exists()
        checks.append({'scope':host+' '+phase,'checks':8,'failed':0,'observations':len(t['observations']),'source_inputs':len(m['source_sha256']),'binary_files':len(m['binary_sha256']),'build_executed':m['build_executed'],'same_offline_binary_reused':phase=='wire'})
    assert manifests[0]['source_sha256']==manifests[1]['source_sha256']==manifests[2]['source_sha256']==manifests[3]['source_sha256']
    assert manifests[0]['deterministic_artifact_sha256']==manifests[1]['deterministic_artifact_sha256']
    for name in manifests[0]['deterministic_artifact_sha256']:assert (phases[0][2]/'contract-proof/deterministic'/name).read_bytes()==(phases[1][2]/'contract-proof/deterministic'/name).read_bytes()
    assert [(x['name'],x['passed']) for x in read(phases[0][2]/'tests.json')['checks']]==[(x['name'],x['passed']) for x in read(phases[1][2]/'tests.json')['checks']]
    assert [(x['name'],x['passed']) for x in read(phases[2][2]/'tests.json')['checks']]==[(x['name'],x['passed']) for x in read(phases[3][2]/'tests.json')['checks']]
    names=[x['name'] for x in dm['phases']];assert dm['engine_revision']==ENGINE and dm['consumer_revision']==revision and all(x['exit']==0 for x in dm['phases'])
    required=['offline-windows','offline-wsl','fixture-start-after-offline','wire-windows','wire-wsl'];assert all(name in names for name in required) and [names.index(name) for name in required]==sorted(names.index(name) for name in required)
    assert dm['builds']==2 and dm['wire_rebuilds']==0 and dm['new_checks_per_host']==16 and dm['prior_full_suites_rerun'] is False
    assert sha(driver_script)==dm['runner_sha256']==sha(driver/'runner.py.txt')
    assert sha(driver/'executing-fixture-setup.py.txt')==dm['fixture_setup_sha256']
    stopped=read(Path(cfg.get('stopped_fixture_evidence',D/'internal/evidence/audit-contract-export/offline-fixture-stopped03.json')));assert stopped['status']=='passed' and stopped['container_running'] is False and stopped['native_listener_count']==0
    checks.append({'scope':'cross-host and root execution controls','targeted_checks_each_host':16,'corrected_candidate_builds':2,'corrected_wire_rebuilds':0,'retained_initial_failed_builds':1,'retained_attempt02_builds':2,'original332_provider_651_security_not_rerun':True,'driver_actual_phases':len(dm['phases']),'same_cross_host_contract_artifact_bytes':True,'fixture_started_only_after_both_offline_lanes':True,'stopped_fixture_and_native_zero_before_offline':True})
    result={'status':'passed_all_declared_review_scopes','reviewed_at_utc':datetime.now(timezone.utc).isoformat(),'reviewer':'independent audit_contract_review agent','engine_revision':ENGINE,'consumer_revision':revision,'original_consumer_revision':ORIGINAL,'second_consumer_revision':SECOND,'new_targeted_checks_per_host':16,'source_input_count':len(finalmap),'corrected_candidate_builds':2,'original_failed_windows_attempt':{'passed':7,'failed':1,'retained':True,'raw_unchanged':True},'second_partial_matrix':{'windows_offline_passed':8,'wsl_offline_passed':8,'windows_wire_failed':8,'wsl_wire_not_executed':True,'retained':True},'phase_results':[{'host':host,'phase':phase,'passed':8,'failed':0,'path':str(root)} for host,phase,root,_,_ in phases],'verified_source_revision_inputs':len(verified_sources),'final_source_sha256':finalmap,'checks':checks,'scope_exclusions':['Root-owned live fixture cleanup and final listener state','Tracking23/Project253/other20row and metadata checks','Publication privacy/SHA256SUMS/index bytes/branch cleanup/push'],'limitations':'Bounded actual fixture/source/binary evidence only. Prior332/651/Core/hosted CI reused baseline; no fresh348/full-suite/benchmark/native Windows DB/external IdP/all-provider/production qualification. M0/#3Blocked/#20original gates unchanged.'}
    data=(json.dumps(result,indent=2)+'\n').encode();local=D/'.local/audit-contract-independent-review.json';public=D/'internal/evidence/audit-contract-export/independent-review.json';assert not local.exists() and not public.exists();local.write_bytes(data);public.parent.mkdir(parents=True,exist_ok=True);public.write_bytes(data)
    print(json.dumps({'status':result['status'],'source_inputs':len(finalmap),'targeted_checks_per_host':16,'actual_driver_phases':len(dm['phases']),'sha256':digest(data)}))

if __name__=='__main__':main()
