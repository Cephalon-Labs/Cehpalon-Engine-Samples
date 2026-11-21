from pathlib import Path
import hashlib,json,subprocess

root=Path.cwd();out=root/'.local/audit-read-admission-host-source';out.mkdir(parents=True,exist_ok=True)
path='audit-outbox/AuditReceiptTransportHost.cs'
baseline='05f119e75bcc2458bee9c610e4ba64f04d4dc6d0'
before=subprocess.check_output(['git','show',baseline+':'+path]);after=(root/path).read_bytes()
changed=subprocess.check_output(['git','diff','--name-only']).decode().splitlines()
assert changed==[path],changed
subprocess.run(['git','diff','--check'],check=True)
assert before.count(b'\r\n')==after.count(b'\r\n')==0
assert after.count(b'new TenantOperationConcurrencyBudget(')==1
assert before.split(b'public sealed record AuditReceiptTransportOptions(',1)[1].split(b')\n{',1)[0]==after.split(b'public sealed record AuditReceiptTransportOptions(',1)[1].split(b')\n{',1)[0]
for name,data in [('before.cs',before),('after.cs',after),('change.diff',subprocess.check_output(['git','diff','--',path]))]:
    (out/name).write_bytes(data)
receipt={'scope':'source-only host implementation; no SDK/provider/fixture execution',
 'baseline':baseline,'changed_files':changed,'before_sha256':hashlib.sha256(before).hexdigest(),
 'after_sha256':hashlib.sha256(after).hexdigest(),'diff_check':'passed','source_lf_preserved':True,
 'positional_options_signature_unchanged':True,'budget_constructor_sites':1,
 'limits':'Fresh-authorized dispatch capacity only; no auth/DTO/wire bound, queue, fairness, distributed capacity or benchmark qualification'}
(out/'source-check.json').write_bytes((json.dumps(receipt,indent=2)+'\n').encode())
preparation={'status':'retained_initial_setup_failure_corrected_cwd',
 'failed_cwd':'D:/Cephalon/Cehpalon-Engine-Docs',
 'failed_git_command':'git worktree add --no-checkout -b features/audit-read-admission-host D:/Cephalon/.worktrees/ara-host 05f119e75bcc2458bee9c610e4ba64f04d4dc6d0',
 'exit_code':1,
 'observed_merged_git_output':"Preparing worktree (new branch 'features/audit-read-admission-host')\nfatal: not a valid branch point: '05f119e75bcc2458bee9c610e4ba64f04d4dc6d0'\n",
 'output_boundary':'Exact git-operation portion retained from merged tool output; command was preceded by read-only Get-Content of ADR0054 in the same PowerShell call. No stdout/stderr separation was provided by the tool.',
 'effect':'Docs did not have the Samples commit; worktree/ref creation rejected. No source, SDK or fixture execution occurred in the failed setup.',
 'correction':'Ran the same git add command from D:/Cephalon/Cehpalon-Engine-Samples; succeeded before source edits. No rejected command re-executed.'}
(root/'.local/audit-read-admission-worktree-preparation.json').write_bytes((json.dumps(preparation,indent=2)+'\n').encode())
print(json.dumps(receipt))
