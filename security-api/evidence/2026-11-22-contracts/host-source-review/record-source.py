from pathlib import Path
import hashlib,json,subprocess
root=Path.cwd();out=root/'.local/ahx-host-source';out.mkdir(parents=True,exist_ok=False)
baseline='e30fd5c97c792b0b78e8838fa3ae1cba69451bb7'
def old(name):return subprocess.check_output(['git','show',baseline+':'+name])
host='audit-outbox/AuditReceiptTransportHost.cs';before=old(host);after=(root/host).read_bytes()
(out/'before-host.cs').write_bytes(before);(out/'after-host.cs').write_bytes(after)
start=b'    static void ValidateSecurity('
assert before[before.index(start):]==after[after.index(start):]
legacy='audit-outbox/Program.cs';original=old(legacy);program=(root/legacy).read_bytes()
lines=b'if(args.Any(x=>x.StartsWith("--export-audit-contracts",StringComparison.Ordinal)))return await AuditReadContractExport.RunCommandAsync(args);\nif(args.Any(x=>x.StartsWith("--verify-audit-contracts",StringComparison.Ordinal)))return await ResourceTransportChecks.RunContractCommandAsync(args);\n'
assert program.replace(lines,b'',1)==original
assert (root/'audit-outbox/README.md').read_bytes().startswith(old('audit-outbox/README.md'))
runtime=after[after.index(b'    public static async ValueTask<AuditReceiptTransportHost> ActivateAsync'):]
ordered=[b'new TenantOperationConcurrencyBudget',b'owner.Probe.BudgetFactories',b'ValidateSelectedReadSettings(options)',b'ArgumentNullException.ThrowIfNull(sourceFactory)',b'owner.Probe.Events.Enqueue("plan.validated")']
assert [runtime.index(x) for x in ordered]==sorted(runtime.index(x) for x in ordered)
files=['audit-outbox/AuditReadTransportCatalog.cs','audit-outbox/AuditReadContractExport.cs',host,legacy,'audit-outbox/README.md']
assert all(b'[Operation(' not in (root/f).read_bytes() for f in files if f.endswith('.cs') and f not in [host,legacy])
subprocess.run(['git','diff','--check'],check=True)
sha={name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in files}
for name in files:
    target=out/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((root/name).read_bytes())
proof={'status':'passed_source_checks_only','baseline':baseline,'source_sha256':sha,'runtime_security_bridge_readers_budget_and_drain_tail_byte_identical':True,'legacy_program_bytes_identical_after_two_early_lines_removed':True,'runtime_budget_probe_timeout_callback_order_preserved':True,'existing_readme_prefix_preserved':True,'new_operation_attributes':0,'sdk_or_fixture_executed':False,'source_review_corrections_before_sdk':['Remove unobserved zero host/source/TLS/authority/budget counters','Include409/422 and bodyless401/405 error semantics','Preserve per-route successful mapping counters on partial failure','Aggregate primary and provider cleanup faults','Remove unused Paths field']}
(out/'source-check.json').write_bytes((json.dumps(proof,indent=2)+'\n').encode())
prep={'status':'retained_preparation_observations','worktree_add_from_samples':'passed','read_only_lookup_failure':'First guessed ADR/requirements/protocol filenames were absent; rg found the canonical offline-audit-read-contract-export/audit-contract-export filenames before source work','source_whitespace_check':'Initial new README appended an extra EOF blank line; trimmed only new EOF and diff --check passed before commit','sdk_or_fixture_executed':False}
(root/'.local/ahx-host-preparation.json').write_bytes((json.dumps(prep,indent=2)+'\n').encode())
(out/'diff.patch.txt').write_bytes(subprocess.check_output(['git','diff','--',host,legacy,'audit-outbox/README.md']))
print(json.dumps({'status':proof['status'],'files':len(files),'source_only':True}))
