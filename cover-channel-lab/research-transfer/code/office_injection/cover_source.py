"""Accept retained isolated captures only after source and membership checks."""
import json
from pathlib import Path
from .cover_registry import digest, validate_coverage
from .source import sha256, read_pcap, write_pcap, transport, epoch
from .path_conformance import check_capture
from .wire_observation import observe_capture, convert_supported_rows



def validate_manifest_identity(job,campaign,events):
    profile=job['profile'];expected_id=profile.get('source_campaign_id',job['job_id'])
    expected_scenario='SEQUENCE_MULTI_PHASE' if profile.get('stage')=='C_sequence' else profile.get('scenario_id',job['entry_id'])
    if campaign.get('campaign_id')!=expected_id or campaign.get('scenario_id')!=expected_scenario:raise ValueError('actual campaign/scenario differs from pinned request')
    if job['entry']['namespace']=='stage_m':
        implementation=profile.get('implementation_id',job.get('profile_id',profile.get('profile_id')))
        if campaign.get('implementation_id')!=implementation or campaign.get('client_impl')!=profile['client']:raise ValueError('actual Stage M implementation/client differs from pinned profile')
    for event in events:
        if event.get('campaign_id')!=expected_id or event.get('scenario_id')!=expected_scenario:raise ValueError('event campaign/scenario identity differs')
        if job['entry']['namespace']=='stage_m' and event.get('implementation_id')!=campaign['implementation_id']:raise ValueError('event implementation differs')
    cadence={'verified':False,'reason':'accelerated or no declared native interval'}
    if job.get('timing')=='native' and job.get('native_interval') and len(events)>1:
        stamps=[epoch(e['sent_at']) for e in events];gaps=[b-a for a,b in zip(stamps,stamps[1:])]
        interval=job['native_interval']
        if min(gaps)<interval*.5 or job['entry_id']=='M-WSS-LONG' and stamps[-1]-stamps[0]<=180:raise ValueError('declared native cadence not observed on events')
        cadence={'verified':True,'requested_interval_seconds':interval,'minimum_gap_seconds':min(gaps),'maximum_gap_seconds':max(gaps),'observed_event_span_seconds':stamps[-1]-stamps[0]}
    return cadence


def ordered_frames(pcap):
    frames=list(read_pcap(pcap,max_regression=.0001))
    regression=max([a[0]-b[0] for a,b in zip(frames,frames[1:])] or [0.])
    ordered=sorted(((i,t,f) for i,(t,f) in enumerate(frames)),key=lambda r:(r[1],r[0]))
    return ordered,{"maximum_regression_seconds":max(0.,regression),"ordering":"stable_event_time_with_original_ordinal"}


def selected_jobs(jobs,requested_only,excluded_profiles=(),excluded_keys=()):
    keys={tuple(k) for k in excluded_keys}
    if excluded_profiles or keys:
        if not requested_only:raise ValueError('profile exclusion requires explicit requested scope')
        available={(j['entry_id'],j['profile_id']) for j in jobs}
        if not keys<=available:raise ValueError('excluded profile key absent from request')
    return [j for j in jobs if j['profile_id'] not in excluded_profiles and (j['entry_id'],j['profile_id']) not in keys]


def timing_fidelity(campaign,driver_timing):
    acceleration=campaign.get('timing_acceleration',1)
    if acceleration!=1:return 'source_accelerated_'+str(acceleration)
    return campaign.get('timing_fidelity',driver_timing)


def import_capture_run(capture_run, registry, out, requested_only=False,excluded_profiles=(),excluded_keys=(),raw_syn_profiles=()):
    root=Path(capture_run);out=Path(out);out.mkdir(parents=True,exist_ok=True)
    runtime=json.loads((root/'runtime_manifest.json').read_text())
    if runtime['registry_sha256']!=registry['sha256'] or runtime.get('exit_code')!=0:
        raise ValueError('incomplete runtime or registry identity mismatch')
    for name,key in (('entrypoint.py','entrypoint_sha256'),('stage_controls.py','control_adapter_sha256'),
                     ('browser_guard.py','browser_guard_sha256'),('mechanic_patch.py','mechanic_patch_sha256'),
                     ('browser_client.py','browser_client_sha256'),('application_patch.py','application_patch_sha256'),('protocol_patch.py','protocol_patch_sha256'),('environment.py','environment_sha256')):
        if key not in runtime:continue
        if sha256(root/'runtime_code'/name)!=runtime[key]:raise ValueError('runtime code snapshot changed')
    jobs=json.loads((root/'jobs.json').read_text())['jobs'];results=json.loads((root/'results.json').read_text())
    by_id={r['job_id']:r for r in results}
    if len(by_id)!=len(results) or set(by_id)!={j['job_id'] for j in jobs}:raise ValueError('missing or duplicated job results')
    jobs=selected_jobs(jobs,requested_only,excluded_profiles,excluded_keys)
    campaigns=[];coverage=[];observations=[]
    for job in jobs:
        result=by_id[job['job_id']];base={k:job[k] for k in ('entry_id','profile_id','arm','registry_sha256')}
        if result.get('status')!='captured':coverage.append({**base,'status':'failed','reason':result.get('reason')});continue
        directory=root/job['job_id'];pcap=directory/'capture.pcap';target=out/job['job_id'];target.mkdir(exist_ok=True)
        if sha256(pcap)!=result['capture_sha256']:raise ValueError('captured PCAP hash changed')
        for name,expected in result.get('evidence_sha256',{}).items():
            if sha256(directory/name)!=expected:raise ValueError('capture evidence changed: '+name)
        dispatch=json.loads((directory/'dispatch.json').read_text())
        if dispatch.get('dispatch_verified') is not True or dispatch.get('catalog_count')!=158:raise ValueError('dispatch hooks not verified')
        manifest=[json.loads(s) for s in (directory/'campaign.jsonl').read_text().splitlines() if s.strip()]
        if len(manifest)!=1 or manifest[0]['campaign_id']!=job['profile'].get('source_campaign_id',job['job_id']):raise ValueError('campaign manifest identity differs')
        campaign=manifest[0];source=campaign.get('source_ip','10.20.0.11')
        events=[json.loads(line) for line in (directory/'events.jsonl').read_text().splitlines() if line]
        if campaign.get('status')!='success' or len(events)!=campaign['expected_events']:raise ValueError('campaign status/event count unverified')
        if campaign.get('generator_name')=='coverlab_sequence_campaign' and ({e.get('phase_name') for e in events} != {'registration','heartbeat','noop_poll','command_poll','result_upload','retry_backoff','reconnect','bulk_result','sleep_change','rotating_poll'} or len(events)!=60):raise ValueError('sequence phases missing')
        cadence=validate_manifest_identity(job,campaign,events)
        start=epoch(campaign['started_at']);end=epoch(campaign['ended_at'])
        path_profile={'status':'not_declared'}
        if job.get('client_mtu') is not None:
            # A declared office path must be on the wire, not just in the request.
            waive=(job['entry_id'],job['profile_id']) in {tuple(k) for k in raw_syn_profiles}
            path_profile=check_capture(pcap,source,job['client_mtu'],job.get('client_tcp_timestamps'),waive_syn=waive)
            if not path_profile['ok']:
                coverage.append({**base,'status':'failed','reason':'path_profile_not_on_wire: '+'; '.join(path_profile['findings'])});continue
            path_profile={**path_profile,'status':'verified_syn_waived_raw_mechanic' if path_profile['waived'] else 'verified','path_profile':job.get('path_profile')}
        ordered,ordering=ordered_frames(pcap)
        frames=[(t,f) for i,t,f in ordered];flow_keys=set()
        # Admit a whole flow only after observing its initiating packet during
        # this job. Delayed FINs from preceding jobs do not gain membership.
        for timestamp,frame in frames:
            p=transport(frame)
            if not p or p['src']!=source or not start<=timestamp<=end:continue
            if p['proto']==17 or p['flags']&0x12==2:flow_keys.add(p['key'])
        selected=[]
        for ordinal,timestamp,frame in ordered:
            p=transport(frame)
            # ICMP is retained in the research observation grain, never
            # converted into a fabricated TCP/UDP session.
            icmp=(len(frame)>=34 and frame[12:14]==b'\x08\x00' and frame[23]==1
                  and (frame[26:30]==b'\x0a\x14\x00\x0b' or frame[30:34]==b'\x0a\x14\x00\x0b')
                  and start<=timestamp<=end)
            if p and p['key'] in flow_keys or icmp:selected.append((ordinal,timestamp,frame))
        if not selected:
            coverage.append({**base,'status':'failed','reason':'no_unambiguous_initiated_wire_instance'});continue
        selected_pcap=target/'campaign.pcap';write_pcap(selected_pcap,[(t,f) for _,t,f in selected])
        first=selected[0][1];last=selected[-1][1]
        precise={'campaign_id':job['job_id'],'source_ip':source,'capture_sha256':sha256(selected_pcap),
                 'started_at':first,'ended_at':last+0.000002,'source_campaign_bounds':[start,end],
                 'membership_policy':'whole_flow_initiated_inside_unique_isolated_job','original_capture_sha256':result['capture_sha256'],
                 'original_packet_ordinals':[i for i,_,_ in selected],'capture_ordering':ordering}
        observation=observe_capture(selected_pcap,precise,target/'observation')
        conversion=convert_supported_rows(observation,target/'conversion')
        observations.append({'campaign_id':job['job_id'],'entry_id':job['entry_id'],'profile_id':job['profile_id'],'arm':job['arm'],
            'observation_sha256':observation['sha256'],'observation_path':str(target/'observation/observation.json'),
            'captured_packets':len(frames),'campaign_packets':len(selected),'auxiliary_or_unassigned_packets':len(frames)-len(selected),
            'cadence_evidence':cadence,'supported_rows':conversion['supported_rows'],'research_only_rows':conversion['separate_observation_rows'],
            'dataset_role':job['entry']['dataset_role'],'source_fidelity':job['entry']['source_fidelity']})
        parent=digest({'entry':job['entry_id'],'profile':job['profile_id'],'seed':job['seed'],'timing':job['timing'],'events':job.get('events',3),'mechanics':job.get('mechanics',False),'native_interval':job.get('native_interval')})
        campaigns.append({'campaign_id':job['job_id'],'parent_campaign_id':parent,'ancestor_group_id':parent,
            'technique':job['entry_id'],'profile_id':job['profile_id'],'arm':job['arm'],'path':str(selected_pcap),
            'sha256':sha256(selected_pcap),'source_start':first,'duration':max(last-first,.000002),'packets':len(selected),
            'generated':True,'source_ip':source,'template_moscow_date':__import__('datetime').datetime.fromtimestamp(first,__import__('zoneinfo').ZoneInfo('Europe/Moscow')).date().isoformat(),
            'dataset_role':job['entry']['dataset_role'],'source_fidelity':job['entry']['source_fidelity'],
            'actual_source_campaign_id':campaign['campaign_id'],'actual_source_scenario_id':campaign['scenario_id'],
            'source_manifest':campaign,'cadence_evidence':cadence,'event_count_verified':len(events),'application_decode_verified':result.get('application_decode_verified'),'fixed_forwarding_verified':result.get('fixed_forwarding_verified'),
            'mechanic':{'client_lib':campaign.get('client_impl','source_dispatch'),'transport':campaign.get('protocol',job['entry'].get('transport','profile_specific')),
                'technique_source':registry['main_commit'] if job['entry']['namespace']=='catalog' else registry['stage_m_commit'],
                'code':job['entry_id']+'__'+job['profile_id'],'description':job['entry'].get('description',job['entry']['family']),
                'carrier':campaign.get('carrier',job['entry']['carrier']),'covert_field':campaign.get('embedding_locus','source_defined'),
                'payload_class':campaign.get('payload_entropy_class','source_defined'),'source_kind':job['entry']['source_fidelity'],
                'c2_framework':'synthetic_local_fixture','timing_source':campaign.get('timing_fidelity','source_native_acceleration_'+str(campaign.get('timing_acceleration',1)))},
            'training_eligible':False,'timing_training_eligible':False,'timing_fidelity':timing_fidelity(campaign,job['timing']),
            'source_capture_sha256':result['capture_sha256'],'observation_sha256':observation['sha256'],
            'modeling_scope':'standard_transport' if conversion['supported_rows'] else 'research_observation_only',
            'path_conformance':path_profile,
            'membership':'physical_capture_whole_instance_inside_unique_isolated_job'})
        coverage.append({**base,'status':'success','wire_evidence':{'capture_sha256':result['capture_sha256'],
            'observed_packets':len(selected),'membership_verified':True,'dispatch_verified':True}})
    report=validate_coverage(registry,coverage,requested_keys=[(j["entry_id"],j["profile_id"],j["arm"]) for j in jobs] if requested_only else None)
    (out/'coverage.json').write_text(json.dumps(report,indent=2)+'\n')
    (out/'catalog.json').write_text(json.dumps({'campaigns':campaigns,'role':'challenge_only','registry_sha256':registry['sha256']},indent=2)+'\n')
    (out/'observation_manifest.json').write_text(json.dumps({'version':'cover-observations-v1','observations':observations,'runtime':runtime},indent=2)+'\n')
    return report
