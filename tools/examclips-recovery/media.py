import importlib.util,json,pathlib,sys
HERE=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('audit_media',HERE.parent/'examclips-audit/diagnostics/audit_diagnostics.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def main():
    mode=sys.argv[1];case=pathlib.Path(sys.argv[2]).resolve()
    if mode=='frame':
        name=sys.argv[3];seconds=float(sys.argv[4])
        if pathlib.Path(name).name!=name or not 0<=seconds<=10800:raise ValueError('invalid frame request')
        out=case/'recovery-frames'/pathlib.Path(name).stem
        out.mkdir(parents=True,exist_ok=True)
        result=m.source_frame(case/name,out,m.q(str(seconds)),m.probe(case/name))
        if result.get('image_file'):result['image_file']=str((out/result['image_file']).relative_to(case))
        print(json.dumps(result));return
    if mode!='diagnostics':raise ValueError('unsupported operation')
    old=m.sample_plan
    def bounded(duration,edl,track,interval=m.q('60'),max_smooth_events=12,frame_interval=m.q('0.06666666666666667')):
        return old(duration,edl,track,interval=interval,max_smooth_events=12,frame_interval=frame_interval)
    m.sample_plan=bounded
    summary=m.inspect_case(case,interval=60,audio_check=False,outdir=case/'recovery-diagnostics',reuse_completed=True)
    summary['recovery_scope']={'uniform_seconds':60,'max_saved_smooth_camera_events_per_clip':12,'continuous_manual_viewing':False,'continuous_manual_listening':False,'quality_verdict':None}
    m.save_json(case/'recovery-diagnostics/diagnostics.json',summary)
    print(json.dumps({'status':summary['status'],'clips':len(summary['clips']),'all_decoded':summary['all_downloaded_files_decoded']}))
if __name__=='__main__':main()
