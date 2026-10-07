import json
import unittest

import pandas as pd

from natural_traffic.behavior import (
    assign_behavior_targets,
    derive_behavior_envelope,
    select_office_web_slice,
)


class OfficeBehaviorProfileTests(unittest.TestCase):
    def _frame(self):
        rows=[]
        for host_idx in range(80):
            for i in range(2):
                rows.append({
                    "host_key": f"h{host_idx:03d}",
                    "ip_protocol": 6,
                    "destination_port": 443,
                    "flow_duration": 0.1 + host_idx * 0.01 + i * 0.001,
                    "pkt_count": 10 + host_idx % 20,
                    "up_pkt_count": 4 + host_idx % 6,
                    "down_pkt_count": 6 + host_idx % 9,
                    "up_bytes": 500 + host_idx * 10,
                    "down_bytes": 1200 + host_idx * 20,
                    "data_pkt_up": 2 + host_idx % 4,
                    "data_pkt_down": 3 + host_idx % 5,
                    "direction_changes": 2 + host_idx % 7,
                    "pkt_len_mean": 200 + host_idx,
                    "pkt_len_p90": 900 + host_idx,
                    "iat_p50": 0.001 + host_idx * 0.0001,
                    "iat_p90": 0.01 + host_idx * 0.0005,
                    "closed_cleanly": 1 if host_idx % 4 else 0,
                    "conn_state": "SF" if host_idx % 4 else "S1",
                    "tls_version": 772 if host_idx % 3 else 771,
                    "tls_alpn_h2": 1 if host_idx % 2 else 0,
                    "tls_alpn_http11": 0 if host_idx % 2 else 1,
                    "tls_ext_count": 12 + host_idx % 5,
                    "tls_cipher_count": 16 + host_idx % 4,
                    "tls_group_count": 4 + host_idx % 3,
                    "tls_sigalg_count": 10 + host_idx % 4,
                    "tls_sni_len": 12 + host_idx % 10,
                })
        return pd.DataFrame(rows)

    def test_web_slice_prefers_tcp_web_ports_when_enough_host_groups_exist(self):
        df=self._frame()
        extra=df.iloc[:10].copy()
        extra["destination_port"]=22
        mixed=pd.concat([df,extra],ignore_index=True)
        selected=select_office_web_slice(mixed,min_host_groups=60)
        self.assertTrue(selected["destination_port"].isin([443,8443,9443]).all())
        self.assertGreaterEqual(selected["host_key"].nunique(),60)

    def test_envelope_is_deterministic_and_records_quantiles_and_categories(self):
        df=self._frame()
        one=derive_behavior_envelope(df,seed=17)
        two=derive_behavior_envelope(df.sample(frac=1,random_state=9),seed=17)
        self.assertEqual(one["sha256"],two["sha256"])
        self.assertEqual(one["version"],"natural-office-behavior-v1")
        self.assertEqual(one["source_policy"],"office_train_only")
        self.assertEqual(one["host_groups"],80)
        self.assertIn("pkt_count",one["numeric"])
        self.assertEqual(set(one["numeric"]["pkt_count"]),{"p10","p25","p50","p75","p90"})
        self.assertAlmostEqual(sum(one["categorical"]["closed_cleanly"].values()),1.0,places=9)
        self.assertIn("772",one["categorical"]["tls_version"])

    def test_envelope_never_contains_labels_or_sensitive_text_fields(self):
        df=self._frame()
        df["label_binary"]=0
        df["url"]="secret"
        df["source_file"]="private"
        body=derive_behavior_envelope(df,seed=3)
        raw=json.dumps(body,sort_keys=True)
        self.assertNotIn("label_binary",raw)
        self.assertNotIn("secret",raw)
        self.assertNotIn("source_file",raw)


    def test_behavior_targets_are_deterministic_bounded_and_profile_specific(self):
        envelope=derive_behavior_envelope(self._frame(),seed=123)
        identities=[f"entry-{i}:profile-{i}" for i in range(12)]
        first=assign_behavior_targets(envelope,identities,seed=777)
        second=assign_behavior_targets(envelope,list(reversed(identities)),seed=777)
        self.assertEqual(first,second)
        self.assertEqual(set(first),set(identities))
        event_bounds=envelope["generation_targets"]["events"]
        allowed_iat=set(envelope["generation_targets"]["iat_seconds"].values())
        allowed_req={int(round(v)) for v in envelope["generation_targets"]["request_bytes"].values()}
        allowed_resp={int(round(v)) for v in envelope["generation_targets"]["response_bytes"].values()}
        observed=set()
        for identity,target in first.items():
            self.assertGreaterEqual(target["runtime_events"],event_bounds["min"])
            self.assertLessEqual(target["runtime_events"],event_bounds["max"])
            self.assertIn(target["native_interval"],allowed_iat)
            self.assertIn(target["benign_request_bytes"],allowed_req)
            self.assertIn(target["benign_response_bytes"],allowed_resp)
            self.assertEqual(target["behavior_profile_sha256"],envelope["sha256"])
            self.assertGreaterEqual(target["benign_sni_len"],5)
            observed.add((
                target["runtime_events"],
                target["native_interval"],
                target["benign_request_bytes"],
                target["benign_response_bytes"],
            ))
        self.assertGreater(len(observed),1)

    def test_behavior_sampler_is_supported_by_empirical_office_ranges(self):
        body=derive_behavior_envelope(self._frame(),seed=123)
        targets=body["generation_targets"]
        self.assertGreaterEqual(targets["events"]["min"],1)
        self.assertLessEqual(targets["events"]["max"],20)
        self.assertGreater(targets["response_bytes"]["p50"],0)
        self.assertGreaterEqual(targets["close_cleanly_probability"],0.0)
        self.assertLessEqual(targets["close_cleanly_probability"],1.0)
        self.assertGreater(targets["iat_seconds"]["p50"],0.0)


if __name__=="__main__":
    unittest.main()