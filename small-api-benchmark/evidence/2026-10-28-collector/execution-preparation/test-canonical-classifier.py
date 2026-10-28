import copy, importlib.util, json, pathlib, sys
root=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root/'tools'))
from benchmark_small_api import diagnostic_preflight_failed
retained=root/'small-api-benchmark/evidence/2026-10-28-tuning/benchmark-observation-03/diagnostics/http/2000-engine/driver/collector-preflight.json'
original=json.loads(retained.read_text())
cases=[]
def check(name,value,expected):
    result=diagnostic_preflight_failed(value,2000)
    assert result is expected,(name,result,expected)
    cases.append({'name':name,'expected_classification':expected,'passed':True})
check('retained actual 37-drop count-consistent report',original,True)
for name,path,value in [
    ('boolean offered count',('preflight','offered'),True),
    ('offered schedule mismatch',('preflight','offered'),3999),
    ('lost count conservation',('preflight','correct'),3962),
    ('unexplained error total',('preflight','errorKinds'),{'offered.dropped':36}),
    ('drop/error kind mismatch',('preflight','dropped'),36),
    ('boolean error-kind count',('preflight','errorKinds'),{'offered.dropped':True}),
    ('empty error-kind label',('preflight','errorKinds'),{'':37}),
    ('impossible successful drain count',('preflight','successfulWithinDrain'),4000),
    ('nonboolean state',('state','passed'),'false'),
]:
    altered=copy.deepcopy(original);altered[path[0]][path[1]]=value;check(name,altered,False)
clean=copy.deepcopy(original);clean['preflight'].update(correct=4000,errors=0,dropped=0,successfulWithinDrain=4000,errorKinds={})
check('successful report is never a failed preflight',clean,False)
bad_state=copy.deepcopy(clean);bad_state['state']['passed']=False
check('count-correct semantic state failure retained',bad_state,True)
for value in (None,[],{}, {'preflight':None,'state':{}}):check('incomplete or incompatible report rejected',value,False)
out={'scope':'Offline classification/metadata robustness; no workload execution or capacity result','assertions':len(cases),'passed':True,'cases':cases}
(root/'.local/canonical-classifier-review.json').write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps({'passed':True,'assertions':len(cases)}))
