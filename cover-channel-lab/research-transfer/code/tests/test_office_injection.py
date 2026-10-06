import io
import struct
import tempfile
import unittest
from pathlib import Path
from collections import Counter

from office_injection.records import merge_rows, profile_rows, choose_placements, RECORD
from office_injection.source import read_pcap, write_pcap, slice_campaigns


def row(ts, source=1, port=50000):
    return RECORD.pack(ts, source.to_bytes(8,'little'), b'\xff'*8, 120, port, 443, 40, 6, 0x18, 1)


class CompositionTests(unittest.TestCase):
    def test_merge_preserves_bytes_order_and_sparse_labels(self):
        with tempfile.TemporaryDirectory() as d:
            d=Path(d); a=d/'a.pkts'; b=d/'b.pkts'
            a.write_bytes(row(1)+row(3)); b.write_bytes(row(2,2))
            stats, gt=merge_rows([a],[{'path':b,'injection_id':'p1','technique':'cc'}],d/'out.pkts')
            self.assertEqual((d/'out.pkts').read_bytes(),row(1)+row(2,2)+row(3))
            self.assertEqual(stats['office_packets'],2)
            self.assertEqual(gt[1]['injection_id'],'p1')
            self.assertEqual(stats['positive_packets'],1)

    def test_many_positive_files_do_not_exhaust_file_descriptors(self):
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        with tempfile.TemporaryDirectory() as d:
            d = Path(d); a = d / 'a.pkts'; a.write_bytes(row(1) + row(9999))
            positives = []
            for i in range(300):
                f = d / f'p{i}.pkts'; f.write_bytes(row(2 + i, 100 + i, 40000 + i) + row(2.5 + i, 100 + i, 40000 + i))
                positives.append({'path': f, 'injection_id': f'p{i}'})
            resource.setrlimit(resource.RLIMIT_NOFILE, (200, hard))       # fewer than the 300 files
            try:stats, gt = merge_rows([a], positives, d / 'out.pkts')
            finally:resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))
            self.assertEqual(stats['positive_packets'], 600)
            self.assertEqual(stats['merged_packets'], 602)

    def test_rejects_endpoint_collision_and_regressing_clock(self):
        with tempfile.TemporaryDirectory() as d:
            d=Path(d); a=d/'a'; b=d/'b'; a.write_bytes(row(1)+row(3))
            b.write_bytes(row(2))
            with self.assertRaisesRegex(ValueError,'collision'):
                merge_rows([a],[{'path':b,'injection_id':'p'}],d/'out')
            b.write_bytes(row(2,2)+row(1,2))
            with self.assertRaisesRegex(ValueError,'timestamp'):
                merge_rows([a],[{'path':b,'injection_id':'p'}],d/'out')

    def test_profiles_and_schedule_use_actual_traffic_and_local_day_period(self):
        with tempfile.TemporaryDirectory() as d:
            d=Path(d); p=d/'office.pkts'
            # Two separate periods: 09:00 and 18:00 MSK, differing load.
            morning=1790143200.0; evening=morning+9*3600
            p.write_bytes(row(morning)+row(morning+19)+b''.join(row(evening+i) for i in range(20)))
            prof=profile_rows([p], interval_seconds=20)
            self.assertEqual(len(prof),2)
            self.assertNotEqual(prof[0]['pps'],prof[1]['pps'])
            placements=choose_placements(prof,[{'campaign_id':'a','duration':1}],seed=17,repeats=2)
            self.assertEqual({x['moscow_hour'] for x in placements},{9,18})
            self.assertEqual(placements,choose_placements(prof,[{'campaign_id':'a','duration':1}],seed=17,repeats=2))

    def test_source_reorder_is_explicit_and_bounded(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'a.pcap'
            write_pcap(p,[(10.0,b'x'*60),(9.999997,b'y'*60)])
            with self.assertRaisesRegex(ValueError,'regression'): list(read_pcap(p))
            self.assertEqual(len(list(read_pcap(p,max_regression=0.00001))),2)
            with self.assertRaisesRegex(ValueError,'regression'): list(read_pcap(p,max_regression=0.000001))

    def test_pcap_shift_preserves_packet_bytes_and_deltas(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'a.pcap';frames=[(10.25,b'x'*60),(10.75,b'y'*60)]
            write_pcap(p,frames,offset=100)
            self.assertEqual(list(read_pcap(p)),[(110.25,b'x'*60),(110.75,b'y'*60)])




class GroundTruthTests(unittest.TestCase):
    def test_checkpoint_and_segment_reset_preserve_observed_membership(self):
        import json
        import extract_office_sessions as office
        from office_injection.assemble import observe_gt
        with tempfile.TemporaryDirectory() as d:
            d=Path(d); p=d/'positive.pkts';p.write_bytes(row(100,2)+row(101,2)+row(102,2))
            a=d/'a.pkts';b=d/'b.pkts';a.write_bytes(row(100,2)+row(101,2));b.write_bytes(row(102,2))
            state=d/'state.pkl';gt1=d/'gt1.jsonl';gt2=d/'gt2.jsonl'
            registry=[{'path':str(p),'injection_id':'one','technique':'cc','campaign_id':'c'}]
            with observe_gt(registry,gt1):
                list(office.session_rows([a],b'fixed',0,1,Counter(),None,state_out=state,finalize=False,max_held=2))
            with observe_gt(registry,gt2):
                rows=list(office.session_rows([b],b'fixed',0,1,Counter(),None,state_in=state,finalize=True,max_held=2))
            labels=[json.loads(x) for x in gt2.read_text().splitlines()]
            self.assertEqual(sum(x['positive_packet_count'] for x in labels),3)
            self.assertEqual(len({x['session_uid'] for x in labels}),1)
            self.assertEqual(len({x['segment_uid'] for x in labels}),2)
            self.assertEqual(len(rows),2)


class AvailabilityTests(unittest.TestCase):
    def test_downgrade_preserves_supported_counts_without_inventing_tls(self):
        import payload_sidecar as pay
        from office_injection.payload import downgrade
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'data.pay';w=pay.SidecarWriter(b'local')
            w.add(100,b'\x01'*8,5000,b'\x02'*8,443,6,100,b'abc',0x18,1)
            with p.open('wb') as f:w.write(f)
            original=list(pay.read_sidecar(p))[0]
            downgrade(p,1);new=list(pay.read_sidecar(p))[0]
            self.assertEqual(new['schema_version'],1)
            self.assertEqual(new['ip_a2b'],original['ip_a2b'])
            self.assertEqual(new['hist_a2b'],original['hist_a2b'])
            self.assertIsNone(new['retx_pkts_a2b'])

class AdmissionAndReplayTests(unittest.TestCase):
    def test_profile_first_timestamp_is_independent_of_path_order(self):
        with tempfile.TemporaryDirectory() as d:
            a=Path(d)/'a';b=Path(d)/'b'
            a.write_bytes(row(1)+row(2));b.write_bytes(row(10)+row(11))
            self.assertEqual(profile_rows([a,b]),profile_rows([b,a]))

    def test_schedule_uses_fitting_period_when_another_period_is_too_short(self):
        p=[{'start':0,'observed_first':0,'observed_last':0.01,'packets':1000,
            'moscow_hour':9,'load_stratum':'low','moscow_date':'2026-09-22','pps':50},
           {'start':100,'observed_first':100,'observed_last':119,'packets':1000,
            'moscow_hour':18,'load_stratum':'high','moscow_date':'2026-09-22','pps':50}]
        self.assertEqual(choose_placements(p,[{'campaign_id':'a','duration':1}],repeats=2)[0]['moscow_hour'],18)

    def test_long_overlapping_campaign_cannot_be_hidden_by_many_other_starts(self):
        import json
        from datetime import datetime,timezone
        from office_injection.source import sha256
        with tempfile.TemporaryDirectory() as d:
            d=Path(d);pcap=d/'a.pcap';manifest=d/'campaigns.jsonl'
            ip=bytearray(20);ip[0]=0x45;ip[9]=6;ip[12:16]=bytes((10,20,0,10));ip[16:20]=bytes((10,20,0,2))
            tcp=bytearray(20);struct.pack_into('!HH',tcp,0,5000,443);tcp[12]=0x50;tcp[13]=2
            f=b'\x00'*12+b'\x08\x00'+bytes(ip)+bytes(tcp)
            write_pcap(pcap,[(20,f),(21,f)])
            def c(i,start,end,source='10.20.0.10'):
                stamp=lambda t:datetime.fromtimestamp(t,timezone.utc).isoformat()
                return {'campaign_id':str(i),'started_at':stamp(start),'ended_at':stamp(end),
                        'source_ip':source,'metadata_revision':2,'positive_only':True,'label_binary':1,'status':'success'}
            campaigns=[c(0,0,100)]+[c(i,10+i/2,10+i/2+0.1,'10.20.0.99') for i in range(1,15)]+[c(99,19,22)]
            manifest.write_text(''.join(json.dumps(x)+'\n' for x in campaigns))
            with self.assertRaisesRegex(ValueError,'no unambiguous'):
                slice_campaigns(pcap,manifest,d/'slices',sha256(pcap))

    def test_load_budget_and_fit_reject_without_changing_source_timing(self):
        profile=[{'start':0,'observed_first':0,'observed_last':19,'packets':1000,
                  'moscow_hour':9,'load_stratum':'low','moscow_date':'2026-09-22','pps':50}]
        c={'campaign_id':'a','duration':1,'packets':8}
        self.assertEqual(len(choose_placements(profile,[c],repeats=1)),1)
        with self.assertRaises(ValueError):choose_placements(profile,[c],repeats=2)
        with self.assertRaises(ValueError):choose_placements(profile,[dict(c,duration=30)])

    def test_missing_and_duplicate_rx_are_rejected(self):
        from office_injection.replay import match_capture
        with tempfile.TemporaryDirectory() as d:
            a=Path(d)/'a.pcap';b=Path(d)/'b.pcap'
            frames=[(1,b'a'*60),(2,b'b'*60)]
            write_pcap(a,frames);write_pcap(b,frames[:1])
            self.assertFalse(match_capture(a,b)['passed'])
            write_pcap(b,frames+[frames[-1]])
            self.assertFalse(match_capture(a,b)['passed'])
            write_pcap(b,frames)
            self.assertTrue(match_capture(a,b)['passed'])

    def test_wire_lineage_distinguishes_coalesced_feature_packets(self):
        import json
        import extract_office_sessions as office
        from office_injection.assemble import observe_gt
        with tempfile.TemporaryDirectory() as d:
            d=Path(d);p=d/'a.pkts'
            p.write_bytes(RECORD.pack(10,b'a'*8,b'b'*8,4000,5000,443,3900,6,0x18,1))
            gt=d/'gt.jsonl';item={'path':str(p),'injection_id':'p','campaign_id':'c'}
            with observe_gt([item],gt):
                rows=list(office.session_rows([p],b'fixed',0,1,Counter(),None,finalize=True))
            lineage=json.loads(gt.with_suffix('.lineage.jsonl').read_text())
            label=json.loads(gt.read_text())
            self.assertEqual(lineage['wire_packet_count'],1)
            self.assertGreater(lineage['feature_packet_count'],1)
            self.assertEqual(label['positive_packet_count'],1)
            self.assertEqual(label['modeled_positive_packet_count'],rows[0][0]['pkt_count'])

class RetentionTests(unittest.TestCase):
    def test_retention_and_failure_logging_errors_still_call_baseline(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        from office_injection.tee import hook
        with tempfile.TemporaryDirectory() as d:
            class Batches:
                work=Path(d);a=SimpleNamespace(batch_seconds=20);logf=None
                def process(self,*args):return 'baseline_processed'
            def bad_log(*args):raise OSError('disk full')
            baseline=SimpleNamespace(Batches=Batches,epoch_name=lambda x:'batch',log=bad_log)
            with patch('office_injection.tee.retain',side_effect=OSError('disk full')), \
                 patch('office_injection.tee.dump',side_effect=OSError('disk full')), \
                 hook(baseline,Path(d)/'spool',8):
                self.assertEqual(Batches().process(0,False,{}),'baseline_processed')

    def test_hardlink_survives_baseline_unlink_and_ready_job_is_idempotent(self):
        from office_injection.tee import retain
        with tempfile.TemporaryDirectory() as d:
            d=Path(d);p=d/'chunk.pkts';q=d/'chunk.pay'
            p.write_bytes(row(1));q.write_bytes(b'OPAY\x01\x00\x00\x00')
            local={1:{'pkts':p,'pay':q}}
            from unittest.mock import patch
            from types import SimpleNamespace
            with patch('office_injection.tee.shutil.disk_usage',return_value=SimpleNamespace(free=10*2**30)):
                m=retain(local,0,20,d/'spool','job',1)
                self.assertEqual(retain(local,0,20,d/'spool','job',1),m)
            p.unlink();q.unlink()
            self.assertEqual(Path(m['inputs'][0]).read_bytes(),row(1))
            self.assertEqual(Path(m['inputs'][0]).with_suffix('.pay').read_bytes(),b'OPAY\x01\x00\x00\x00')

    def test_full_second_branch_does_not_interrupt_baseline(self):
        from types import SimpleNamespace
        from office_injection.tee import hook
        with tempfile.TemporaryDirectory() as d:
            d=Path(d);p=d/'chunk.pkts';q=d/'chunk.pay'
            p.write_bytes(row(1));q.write_bytes(b'OPAY\x01\x00\x00\x00')
            class Batches:
                work=d;a=SimpleNamespace(batch_seconds=20);logf=None
                def process(self,*args):return 'baseline_processed'
            baseline=SimpleNamespace(Batches=Batches,epoch_name=lambda x:'batch',log=lambda *x:None)
            with hook(baseline,d/'spool',0):
                self.assertEqual(Batches().process(0,False,{1:{'pkts':p,'pay':q}}),'baseline_processed')
            self.assertTrue(p.exists())
            self.assertTrue(list((d/'spool').glob('*.failed.json')))

class AuditFeatureSelectionTests(unittest.TestCase):
    def test_real_channel_features_are_not_dropped_by_annotation_keywords(self):
        from office_injection.audit import numeric
        for name in ('dns_label_entropy','ra_keystroke_iat_p50','tls_version'):
            with self.subTest(name=name):self.assertEqual(numeric(name,'1.25'),1.25)

    def test_annotations_and_unknown_numeric_columns_never_enter_the_audit(self):
        from office_injection.audit import numeric
        for name in ('label_binary','training_eligible','host_key','segment_uid',
                     'y_presumed','campaign_id','schema_version','unknown_added_column'):
            with self.subTest(name=name):self.assertIsNone(numeric(name,'1'))

if __name__=='__main__': unittest.main()
