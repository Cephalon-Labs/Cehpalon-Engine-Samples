from pathlib import Path
import hashlib,json
D=Path.cwd();B=Path('D:/Cephalon');decl=D/'.local/audit-contract-export-declaration03';decl.mkdir(exist_ok=False);rel='internal/validation/audit-contract-export-fixture-correction.md';data=(D/rel).read_bytes();target=decl/rel;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
(decl/'manifest.json').write_bytes((json.dumps({'status':'frozen_before_fixture_corrected_sdk','files':{rel:hashlib.sha256(data).hexdigest()},'reason':'New fixture schema prefix must satisfy unchanged owned-schema guard','source_change':'New AuditContractChecks literal ac_ to ao_ only','assertions_and_provider_guard_changed':False,'original_criteria_unchanged':True,'all_original_attempts_retained':True},indent=2)+'\n').encode())
text=(D/'.local/freeze-audit-contract-export-source02.py').read_text(encoding='utf-8').replace('audit-contract-export-source02','audit-contract-export-source03').replace("('01','02')","('01','02','03')");(D/'.local/freeze-audit-contract-export-source03.py').write_bytes(text.encode())
text=(D/'.local/setup-audit-contract-export-fixture.py').read_text(encoding='utf-8').replace("new=Path('D:/Cephalon/.worktrees/ahx-consumer/.local')","new=Path('D:/Cephalon/.worktrees/ahx-consumer/.local/fixture03')").replace('new.mkdir(exist_ok=True)','new.mkdir(parents=True,exist_ok=True)')
needle=".replace('audit contract export consumer','audit contract export consumer')"
original=".replace('audit read admission consumer','audit contract export consumer')"
assert original in text;text=text.replace(original,original+".replace('/ahx-consumer/.local','/ahx-consumer/.local/fixture03')")
(D/'.local/setup-audit-contract-export-fixture03.py').write_bytes(text.encode())
text=(D/'.local/check-audit-contract-export-offline-fixture.py').read_text(encoding='utf-8').replace("prior=Path('D:/Cephalon/.worktrees/ara-consumer/.local')","prior=Path('D:/Cephalon/.worktrees/ahx-consumer/.local')").replace('audit-read-admission-fixture-cleanup.json','audit-contract-export-fixture-cleanup.json').replace('offline-fixture-stopped.json','offline-fixture-stopped03.json').replace('ahx-consumer/.local/private-pg18-connection.env','ahx-consumer/.local/fixture03/private-pg18-connection.env')
(D/'.local/check-audit-contract-export-offline-fixture03.py').write_bytes(text.encode())
text=(D/'.local/run-audit-contract-export02.py').read_text(encoding='utf-8').replace('ahx-driver02','ahx-driver03').replace('offline-fixture-stopped.json','offline-fixture-stopped03.json').replace('setup-audit-contract-export-fixture.py','setup-audit-contract-export-fixture03.py')
for part in ('offline-windows','offline-wsl','wire-windows','wire-wsl'):text=text.replace('ahx-'+part+'02','ahx-'+part+'03')
text=text.replace("decl2=D/'.local/audit-contract-export-declaration02'","decl2=D/'.local/audit-contract-export-declaration02';decl3=D/'.local/audit-contract-export-declaration03'")
text=text.replace("'--declarations-root',decl2]","'--declarations-root',decl2,'--declarations-root',decl3]").replace("'--declarations-root',unix(decl2)]","'--declarations-root',unix(decl2),'--declarations-root',unix(decl3)]")
start=text.index('    assert not SW.exists();SW.mkdir();');end=text.index("    wsl(SW,['python3'",start)
replacement="""    assert SW.is_dir()
    assert not wsl(SW,['git','status','--porcelain'],'wsl-existing-clean').strip()
    old=wsl(SW,['git','rev-parse','HEAD'],'wsl-existing-head').decode().strip();assert old=='d013d61ae2cc22f2d79fefc29fd64482b4888f13'
    wsl(SW,['git','merge-base','--is-ancestor',old,a.consumer_revision],'wsl-source-forward-check')
    wsl(SW,['git','update-ref','refs/heads/features/audit-contract-export-source',a.consumer_revision,old],'wsl-source-ref-forward')
    wsl(SW,['git','checkout','--detach',a.consumer_revision],'wsl-source-detach');assert not wsl(SW,['git','status','--porcelain'],'wsl-source-state').strip()
    (O/'wsl-source-borrowing.json').write_bytes((json.dumps({'source':str(SW),'previous_source':old,'consumer_revision':a.consumer_revision,'borrowed_objects':'/mnt/d/Cephalon/Cehpalon-Engine-Samples/.git/objects','independent_source_archive':False,'retain_primary_objects_worktrees_and_old_outputs':True},indent=2)+'\\n').encode())
"""
text=text[:start]+replacement+text[end:]
text=text.replace("S/'.local/private-pg18-","S/'.local/fixture03/private-pg18-").replace("S/'.local/postgres18-fixture.json'","S/'.local/fixture03/postgres18-fixture.json'")
for p in (D/'.local/run-audit-contract-export03.py',B/'.worktrees/arh-engine/.local/run-audit-contract-export03.py'):p.write_bytes(text.encode())
print(json.dumps({'declaration03_frozen':True,'original02_raw_and_guard_preserved':True,'new_driver':'ahx-driver03','helper_directory':'.local/fixture03','provider_guard_relaxed':False}))
