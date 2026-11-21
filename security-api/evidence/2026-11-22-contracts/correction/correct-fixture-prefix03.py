from pathlib import Path
import hashlib,json,subprocess
root=Path.cwd();out=root/'.local/ahx-fixture-correction03';out.mkdir(exist_ok=False)
source=root/'audit-outbox/AuditContractChecks.cs';provider=root/'audit-outbox/PostgresStore.cs'
before=source.read_bytes();provider_before=provider.read_bytes()
assert subprocess.check_output(['git','rev-parse','HEAD']).decode().strip()=='d013d61ae2cc22f2d79fefc29fd64482b4888f13'
assert not subprocess.check_output(['git','status','--porcelain']).strip()
assert before.count(b'"ac_" + Guid.NewGuid().ToString("N")')==1
after=before.replace(b'"ac_" + Guid.NewGuid().ToString("N")',b'"ao_" + Guid.NewGuid().ToString("N")',1)
(out/'before.cs.txt').write_bytes(before);source.write_bytes(after);(out/'after.cs.txt').write_bytes(after)
assert provider.read_bytes()==provider_before
diff=subprocess.check_output(['git','diff','--','audit-outbox/AuditContractChecks.cs']);(out/'correction.diff.txt').write_bytes(diff)
assert len([line for line in diff.splitlines() if line.startswith(b'-') and not line.startswith(b'---')])==1
assert len([line for line in diff.splitlines() if line.startswith(b'+') and not line.startswith(b'+++')])==1
assert subprocess.check_output(['git','diff','--name-only']).decode().splitlines()==['audit-outbox/AuditContractChecks.cs']
r={'status':'source_correction_only','base_revision':'d013d61ae2cc22f2d79fefc29fd64482b4888f13','reason':'New targeted test fixture used ac_ but unchanged PostgresStore requires owned ao_ plus32 lowercase hexadecimal characters. The original Winwire02 0/8 attempt remains retained by root.','change':'Exactly one literal ac_ to ao_ in new AuditContractChecks fixture constructor','before_sha256':hashlib.sha256(before).hexdigest(),'after_sha256':hashlib.sha256(after).hexdigest(),'provider_regex_source_unchanged':True,'provider_sha256':hashlib.sha256(provider_before).hexdigest(),'old332_suite_unchanged':True,'sdk_fixture_or_remote_operation':False,'source_script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
(out/'source-proof.json').write_text(json.dumps(r,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'status':r['status'],'changed_lines':1,'provider_unchanged':True,'sdk_executed':False}))
