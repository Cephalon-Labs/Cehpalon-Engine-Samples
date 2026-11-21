"""Keep all arm distributions and paired interval differences; no point-estimate scheduler share."""
import argparse
import hashlib
import json
from pathlib import Path
from statistics import mean,median

from analyze_timer_publication import read


def summarize(report):
    groups=[];pairs=[]
    for profile in range(1,5):
        metrics=['request_to_observed_resume'] if profile==1 else ['arm_or_enqueue_to_callback','publication_to_observed_resume']
        for observed in [False,True]:
            cases=[c for c in report['cases'] if c['observed']==observed]
            selected=[next(g for g in c['groups'] if g['profile']==profile) for c in cases]
            row={'profile':profile,'observed':observed,'trials':sum(g['trials'] for g in selected),
                 'inline_observed':sum(g['inline_observed'] for g in selected),
                 'publication_after_point_races':sum(g.get('publication_after_point_races',0) for g in selected),'metrics':{}}
            for metric in metrics:
                row['metrics'][metric]={bound:{'arm_means':[g[metric][bound]['mean'] for g in selected],
                    'arm_medians':[g[metric][bound]['median'] for g in selected],
                    'arm_p95':[g[metric][bound]['p95_nearest_rank'] for g in selected],
                    'minimum':min(g[metric][bound]['minimum'] for g in selected),'maximum':max(g[metric][bound]['maximum'] for g in selected)} for bound in ['lower_ms','upper_ms']}
            groups.append(row)
        for pair in range(1,5):
            cases=[c for c in report['cases'] if c['name'].startswith(f'{pair:02d}-')]
            control=next(g for c in cases if not c['observed'] for g in c['groups'] if g['profile']==profile)
            trace=next(g for c in cases if c['observed'] for g in c['groups'] if g['profile']==profile)
            pairs.append({'profile':profile,'pair':pair,'differences':{metric:{bound:trace[metric][bound]['mean']-control[metric][bound]['mean'] for bound in ['lower_ms','upper_ms']} for metric in metrics}})
    traced=[c for c in report['cases'] if c['observed']]
    overlap={}
    for key in ['whole_window','callback_leg_window','guaranteed_post_publication_window']:
        windows=[t[key] for c in traced for t in c['trials'] if t.get(key) is not None]
        overlap[key]={'windows':len(windows),'with_gc_inner':sum(w['client']['gc_inner_overlap_ms']>0 for w in windows),
                      'with_gc_envelope':sum(w['client']['gc_envelope_overlap_ms']>0 for w in windows)}
    return {'status':'summarized','trials':sum(len(c['trials']) for c in report['cases']),
            'marker_count':sum(c['capture']['marker_count'] for c in traced),'groups':groups,'paired_interval_differences':pairs,
            'recorded_gc_overlap':overlap,'qualification':False,
            'summary_source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'scope':'Bounds and distributions retained separately. Differences include observer/OS/runtime work. No kernel-ready timestamp or historical-drop attribution.'}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--input',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    with args.output.open('x',encoding='utf-8',newline='\n') as file:json.dump(summarize(read(args.input)),file,indent=2);file.write('\n')
