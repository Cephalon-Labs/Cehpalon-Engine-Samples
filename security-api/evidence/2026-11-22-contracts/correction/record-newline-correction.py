from pathlib import Path
import hashlib,json,subprocess
root=Path.cwd();out=root/'.local/ahx-newline-correction02';out.mkdir(parents=True,exist_ok=False)
name='audit-outbox/AuditReadContractExport.cs';baseline='e97e0db600de8d3daa710d6d4b3e04592dd9a4fb'
before=subprocess.check_output(['git','show',baseline+':'+name]);after=(root/name).read_bytes()
old=b'static readonly JsonSerializerOptions Json = new() { IncludeFields = true, WriteIndented = true };'
new=b'static readonly JsonSerializerOptions Json = new() { IncludeFields = true, WriteIndented = true, NewLine = "\\n" };'
assert before.count(old)==1 and after==before.replace(old,new,1)
assert b'OpenApi(catalog, counters).ToJsonString(Json)' in after and b'}, Json) + "\\n"' in after
(out/'before.cs').write_bytes(before);(out/'after.cs').write_bytes(after)
ref=Path('D:/Cephalon/.tools/dotnet11-ga/win-x64/packs/Microsoft.NETCore.App.Ref/11.0.0/ref/net11.0/System.Text.Json.xml')
data=ref.read_bytes();start=data.index(b'<member name="P:System.Text.Json.JsonSerializerOptions.NewLine">');end=data.index(b'</member>',start)+len(b'</member>');(out/'dotnet11-reference-excerpt.xml.txt').write_bytes(data[start:end])
(out/'diff.patch.txt').write_bytes(subprocess.check_output(['git','diff','--',name]))
subprocess.run(['git','diff','--check'],check=True)
report={'status':'passed_source_only_correction','baseline':baseline,'file':name,'before_sha256':hashlib.sha256(before).hexdigest(),'after_sha256':hashlib.sha256(after).hexdigest(),'change':'One options initializer adds explicit LF NewLine for shared OpenAPI and manifest serialization','local_dotnet11_reference':str(ref),'reference_sha256':hashlib.sha256(data).hexdigest(),'reference_default':'Environment.NewLine','initial_failed_outputs_unchanged':True,'test_criteria_unchanged':True,'sdk_fixture_or_remote_executed':False}
(out/'source-check.json').write_bytes((json.dumps(report,indent=2)+'\n').encode());print(json.dumps({'status':report['status'],'changed_files':1,'initializer_only':True}))
