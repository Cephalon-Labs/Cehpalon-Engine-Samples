import hashlib,json,subprocess,sys,datetime
from pathlib import Path
root=Path.cwd();engine=Path('D:/Cephalon/.worktrees/arh-engine');mode=sys.argv[1];assert mode in ('precommit-index','postcommit-byte')
freeze=json.loads((root/'.local/resource-transport-windows-dev01-source/manifest.json').read_bytes());run=json.loads((root/'.local/resource-transport-windows-dev01/manifest.json').read_bytes());assert run['status']=='passed' and run['total_passed']==308
source={}
for key,digest in freeze['source_sha256'].items():
 prefix,rel=key.split('/',1);repo=engine if prefix=='engine' else root;data=(repo/rel).read_bytes();assert hashlib.sha256(data).hexdigest()==digest,key;frozen=(root/'.local/resource-transport-windows-dev01-source/frozen-source'/key).read_bytes();assert frozen==data,key;source[key]=digest
assert len(source)==110 and len(run['source_sha256'])==109 and all(source[k]==v for k,v in run['source_sha256'].items())
paths=['audit-outbox/ResourceTransportChecks.cs','audit-outbox/Program.cs','audit-outbox/README.md','tools/verify_audit_outbox.py'];blobs={}
for rel in paths:
 data=(root/rel).read_bytes();assert b'\r\n' not in data,rel;spec=(':'+rel) if mode=='precommit-index' else ('HEAD:'+rel);blob=subprocess.check_output(['git','show',spec],cwd=root);assert data==blob,rel;blobs[rel]={'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),'CRLF_count':0,'exact_git_blob':True}
if mode=='postcommit-byte':
 for key,digest in source.items():
  prefix,rel=key.split('/',1);repo=engine if prefix=='engine' else root;blob=subprocess.check_output(['git','show','HEAD:'+rel],cwd=repo);assert hashlib.sha256(blob).hexdigest()==digest,key
report={'status':'passed','utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'mode':mode,'consumer_revision':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'engine_revision':run['engine_revision'],'frozen_source_count':110,'verifier_source_count':109,'all_current_frozen_equal':True,'all_executing_source_git_blobs_equal':mode=='postcommit-byte','changed_files':blobs,'total_passed':308,'source_sha256':source}
out=root/'.local'/('resource-transport-'+('precommit-index-proof' if mode=='precommit-index' else 'postcommit-byte-proof')+'.json');assert not out.exists();out.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps({k:v for k,v in report.items() if k not in ('source_sha256','changed_files')}))
