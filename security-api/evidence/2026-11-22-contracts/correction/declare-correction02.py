from pathlib import Path
import hashlib,json
D=Path.cwd();decl=D/'.local/audit-contract-export-declaration02';decl.mkdir(exist_ok=False);rel='internal/validation/audit-contract-export-lf-correction.md';data=(D/rel).read_bytes();target=decl/rel;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
(decl/'manifest.json').write_bytes((json.dumps({'status':'frozen_before_corrected_sdk','files':{rel:hashlib.sha256(data).hexdigest()},'reason':'Explicit LF writer policy after original Windows offline7pass1fail','source_change':'Shared JsonSerializerOptions.NewLine only','tests_changed':False,'original_criteria_unchanged':True,'original_attempt_retained':True},indent=2)+'\n').encode())
original=(D/'.local/freeze-audit-contract-export-source.py').read_text(encoding='utf-8').replace('audit-contract-export-source01','audit-contract-export-source02')
start=original.index("declarations={};decl=D/");end=original.index("m={'status'",start)
replacement="""declarations={}
for version in ('01','02'):
    decl=D/('.local/audit-contract-export-declaration'+version)
    for f in sorted(decl.rglob('*')):
        if f.is_file():
            rel=f.relative_to(decl);key=version+'/'+rel.as_posix();data=f.read_bytes();target=out/'declaration'/key;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data);declarations[key]=hashlib.sha256(data).hexdigest()
"""
original=original[:start]+replacement+original[end:];(D/'.local/freeze-audit-contract-export-source02.py').write_bytes(original.encode())
text=(D/'.local/run-audit-contract-export.py').read_text(encoding='utf-8').replace('ahx-driver01','ahx-driver02')
for part in ('offline-windows','offline-wsl','wire-windows','wire-wsl'):text=text.replace('ahx-'+part+'01','ahx-'+part+'02')
text=text.replace("decl=D/'.local/audit-contract-export-declaration01'","decl=D/'.local/audit-contract-export-declaration01';decl2=D/'.local/audit-contract-export-declaration02'")
text=text.replace("'--declarations-root',decl]","'--declarations-root',decl,'--declarations-root',decl2]").replace("'--declarations-root',unix(decl)]","'--declarations-root',unix(decl),'--declarations-root',unix(decl2)]")
for path in (D/'.local/run-audit-contract-export02.py',Path('D:/Cephalon/.worktrees/arh-engine/.local/run-audit-contract-export02.py')):path.write_bytes(text.encode())
print(json.dumps({'declaration02_frozen':True,'original_driver_and_raw_unchanged':True,'next_driver':'ahx-driver02','all_four_phase_output_suffix':'02','test_and_benchmark_criteria_unchanged':True}))
