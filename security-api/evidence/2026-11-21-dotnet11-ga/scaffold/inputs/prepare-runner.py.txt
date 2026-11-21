from pathlib import Path
import json,hashlib
source=Path('D:/Cephalon/.worktrees/ga-consumer');target=Path('D:/Cephalon/.worktrees/ga-scaffold');target.mkdir(exist_ok=False)
report={'scope':'Separate GA functional scaffold inputs; historical tracked lock not edited','source_revision':'66db9282a2273c941d50c608bb0d1334167ae6eb','copied_bytes_sha256':{}}
for name in ['tools/verify_tooling_small_api.py','tools/analyze_live_budget_metrics.py','global.json','NuGet.Config']:
 data=(source/name).read_bytes();p=target/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data);report['copied_bytes_sha256'][name]=hashlib.sha256(data).hexdigest()
data=(source/'tooling-small-api/engine-lock.json').read_bytes();(target/'original-historical-lock.json').write_bytes(data);old=json.loads(data);new=dict(old,engine_revision='b68d8e8705a48ea9a815b72126b05deedf2351b9',sdk='11.0.100',scope='Separate .NET11 GA functional scaffold regression; original RC lock/source/benchmark evidence unchanged; no full benchmark qualification')
p=target/'tooling-small-api/engine-lock.json';p.parent.mkdir();p.write_text(json.dumps(new,indent=2)+'\n',encoding='utf-8');report['original_lock_sha256']=hashlib.sha256(data).hexdigest();report['new_lock_sha256']=hashlib.sha256(p.read_bytes()).hexdigest();report['new_lock']=new
(target/'inputs-frozen-before-sdk.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');(target/'prepare-runner.py.txt').write_bytes(Path(__file__).read_bytes());print(json.dumps(report))
