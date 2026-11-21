from pathlib import Path
import ast,json,hashlib,subprocess
ast.parse(Path('tools/verify_audit_contracts.py').read_text(encoding='utf-8'))
text=Path('audit-outbox/AuditContractChecks.cs').read_text(encoding='utf-8')
assert text.count('await check("offline ')==8
assert text.count('await check(label + ')==4
marker=b'var arguments=args.Select'
old=subprocess.check_output(['git','show','e30fd5c97c792b0b78e8838fa3ae1cba69451bb7:audit-outbox/Program.cs'])
current=Path('audit-outbox/Program.cs').read_bytes()
assert old[old.index(marker):]==current[current.index(marker):]
result={'status':'passed_source_only','verifier_ast':True,'new_offline_cases':8,'new_wire_cases_per_transport':4,'total_per_host':16,'normal_program_tail_identical':True,'sdk_executed':False,'files':{name:hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in ['audit-outbox/AuditContractChecks.cs','tools/verify_audit_contracts.py']},'retained_preparation_failure':{'stage':'PowerShell inline checker parse','error':'ParserError: Missing closing parenthesis in expression caused by nested quoted Python source; entire command rejected before git add/check execution','correction':'Use this file-backed checker instead of shell-embedded Python quoting','sdk_or_product_execution':False}}
Path('.local/audit-contract-test-source-check.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'status':result['status'],'total_per_host':16,'sdk_executed':False}))
