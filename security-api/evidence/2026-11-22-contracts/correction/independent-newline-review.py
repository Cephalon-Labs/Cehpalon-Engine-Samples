from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,subprocess
D=Path.cwd();H=Path('D:/Cephalon/.worktrees/ahx-export');S=Path('D:/Cephalon/.worktrees/ahx-consumer');before='e97e0db600de8d3daa710d6d4b3e04592dd9a4fb';after='e0e7e56a705374f5126e5b2f8caa8abb63f8b9e6';name='audit-outbox/AuditReadContractExport.cs';out=D/'.local/audit-contract-newline-correction-review.json';assert not out.exists()
def git(*args):return subprocess.check_output(['git','-C',str(H),*args])
old=git('show',before+':'+name);new=git('show',after+':'+name)
needle=b'IncludeFields = true, WriteIndented = true';replacement=needle+b', NewLine = "\\n"'
assert old.count(needle)==1 and new==old.replace(needle,replacement,1)
assert git('diff','--name-only',before,after).decode().splitlines()==[name]
assert (H/name).read_bytes()==new and git('rev-parse','HEAD').decode().strip()==after and not git('status','--porcelain').strip()
failed=S/'.local/ahx-offline-windows01';m=json.loads((failed/'manifest.json').read_bytes());tests=json.loads((failed/'tests.json').read_bytes())
assert m['status']=='failed' and m['passed']==7 and m['failed']==1 and tests['passed']==7 and tests['failed']==1
negative=[x for x in tests['checks'] if not x['passed']];assert len(negative)==1 and negative[0]['name']=='offline deterministic UTF8 LF payload bytes and manifest hashes'
assert m['consumer_revision']=='acba0da39f9d50204627ff75ac135d8b50af2180' and m['source_sha256']['consumer/'+name]==hashlib.sha256(old).hexdigest()
raw={}
for filename in ('openapi.json','manifest.json','schema.graphql'):
    path=failed/'contract-proof/cli-both'/filename;data=path.read_bytes();raw[filename]={'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),'CRLF':data.count(b'\r\n'),'LF':data.count(b'\n')}
assert raw['openapi.json']['CRLF']>0 and raw['manifest.json']['CRLF']>0 and raw['schema.graphql']['CRLF']==0
build=(failed/'build.stdout.txt').read_text();assert '0 Warning(s)' in build and '0 Error(s)' in build and 'Build succeeded.' in build
reference=Path('D:/Cephalon/.tools/dotnet11-ga/win-x64/packs/Microsoft.NETCore.App.Ref/11.0.0/ref/net11.0/System.Text.Json.xml');text=reference.read_text();fragment=text.split('name="P:System.Text.Json.JsonSerializerOptions.NewLine"',1)[1].split('</member>',1)[0];assert 'Environment.NewLine' in fragment
r={'status':'passed_source_correction_review_only','reviewed_at_utc':datetime.now(timezone.utc).isoformat(),'reviewer':'independent audit_contract_review agent','before_revision':before,'correction_revision':after,'changed_files':[name],'before_sha256':hashlib.sha256(old).hexdigest(),'after_sha256':hashlib.sha256(new).hexdigest(),'exact_single_options_property_addition':True,'test_and_protocol_criteria_changed':False,'original_failed_execution':{'path':str(failed),'status':'failed','passed':7,'failed':1,'failed_check':negative[0]['name'],'build_warnings':0,'build_errors':0,'manifest_sha256':hashlib.sha256((failed/'manifest.json').read_bytes()).hexdigest(),'tests_sha256':hashlib.sha256((failed/'tests.json').read_bytes()).hexdigest(),'retained_cli_artifacts':raw},'local_sdk_reference':{'path':str(reference),'sha256':hashlib.sha256(reference.read_bytes()).hexdigest(),'documented_default':'Environment.NewLine'},'interpretation':'Platform default pretty-JSON line endings account for observed CRLF in both JSON outputs while SDL already used explicit LF. The source correction selects LF at serialization time; corrected execution and cross-host determinism remain to be tested.','raw_normalized_or_overwritten':False,'sdk_or_fixture_or_remote_execution_by_reviewer':False,'limitations':'Exact source delta and original raw inspection only, not a corrected runtime pass or production qualification.'}
out.write_bytes((json.dumps(r,indent=2)+'\n').encode());print(json.dumps({'status':r['status'],'changed_files':1,'original_failed_counts':[7,1],'raw_CRLF':{k:v['CRLF'] for k,v in raw.items()},'sha256':hashlib.sha256(out.read_bytes()).hexdigest()}))
