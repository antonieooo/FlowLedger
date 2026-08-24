package ledger

import (
	"encoding/json"
	"sort"
	"testing"

	"FlowLedger/pkg/features"
)

// v1alpha4RecordKeys is the AUTHORITATIVE v1alpha4 JSON surface: it was read
// back out of the frozen corpus B ledger
// (/mnt/.../adopted-corpus/unit-1/raw-fl-worker.jsonl.gz, first 20k records),
// not transcribed from this repo's structs, so it cannot drift with the code
// it is meant to police.
var v1alpha4RecordKeys = []string{
	"action_suggestion",
	"agent_id",
	"alpn",
	"alpn_negotiated",
	"burst_count",
	"byte_rate",
	"byte_ratio_out_in",
	"bytes_in",
	"bytes_out",
	"bytes_per_second_in",
	"bytes_per_second_out",
	"bytes_total",
	"close_reason",
	"cluster_id",
	"collection_mode",
	"conn_end_time",
	"conn_start_time",
	"counter_epoch",
	"counter_reset_count",
	"counter_reset_detected",
	"counter_semantics",
	"cross_namespace",
	"direction",
	"direction_changes",
	"direction_duration_available",
	"direction_duration_in_ms",
	"direction_duration_out_ms",
	"dst_app_protocol",
	"dst_cgroup_id",
	"dst_container_id",
	"dst_container_name",
	"dst_external",
	"dst_identity_resolution_status",
	"dst_image_digest",
	"dst_ip",
	"dst_is_service_backend",
	"dst_mapping_confidence",
	"dst_namespace",
	"dst_node",
	"dst_pod_name",
	"dst_pod_template_hash",
	"dst_pod_uid",
	"dst_port",
	"dst_replicaset",
	"dst_revision",
	"dst_service_account",
	"dst_service_name",
	"dst_service_namespace",
	"dst_service_port_name",
	"dst_service_uid",
	"dst_workload_kind",
	"dst_workload_name",
	"dst_workload_uid",
	"duration_ms",
	"end_time",
	"expected_edge",
	"experiment_id",
	"fast_model_version",
	"fast_score",
	"fast_threshold",
	"feature_set_version",
	"fin_count",
	"final_window",
	"flow_id",
	"handshake_seen",
	"histogram_truncated",
	"hook_source",
	"hpa_scaling_window",
	"iat_histogram",
	"iat_mean",
	"iat_overflow",
	"iat_p50",
	"iat_p95",
	"iat_std",
	"idle_gap_count",
	"ip_family",
	"ip_pkt_len_available",
	"ip_pkt_len_max",
	"ip_pkt_len_min",
	"ip_ttl_available",
	"ip_ttl_max",
	"ip_ttl_min",
	"is_long_lived",
	"is_tls_like",
	"ja4",
	"ja4s",
	"local_retrans_available",
	"local_retrans_skb_bytes",
	"local_retrans_skb_count",
	"local_retrans_source",
	"mapping_method",
	"netflow_v2_ip_size_histogram",
	"netflow_v2_ip_size_histogram_available",
	"netns_ino",
	"network_policy_allowed",
	"node_name",
	"node_visibility_degraded",
	"observed_skb_packets_available",
	"observed_skb_packets_in",
	"observed_skb_packets_out",
	"observed_skb_packets_source",
	"observed_skb_packets_total",
	"packet_rate",
	"packet_ratio_out_in",
	"packet_timing_available",
	"packets_in",
	"packets_out",
	"packets_total",
	"payload_collected",
	"peer_retrans_available",
	"peer_retrans_skb_bytes",
	"peer_retrans_skb_count",
	"pkt_size_histogram",
	"pkt_size_max",
	"pkt_size_mean",
	"pkt_size_min",
	"pkt_size_p50",
	"pkt_size_p95",
	"pkt_size_std",
	"pod_restart_window",
	"policy_confidence",
	"protocol",
	"protocol_guess",
	"reason_codes",
	"record_type",
	"retention_tier",
	"retrans_count",
	"review_id",
	"review_required",
	"review_score",
	"review_verdict",
	"rollout_window",
	"rst_count",
	"rtt_estimate_us",
	"same_namespace",
	"same_workload",
	"sampling_applied",
	"sampling_rate",
	"sampling_reason",
	"scenario_label",
	"schema_version",
	"server_hello_seen",
	"sni_hash",
	"sni_visibility",
	"src_cgroup_id",
	"src_container_id",
	"src_container_name",
	"src_identity_attempts",
	"src_identity_frozen",
	"src_identity_missing_reason",
	"src_identity_observed_time",
	"src_identity_resolution_method",
	"src_identity_resolution_status",
	"src_image_digest",
	"src_ip",
	"src_key_g2_available",
	"src_key_g3_available",
	"src_key_g4_available",
	"src_mapping_confidence",
	"src_namespace",
	"src_node",
	"src_pod_name",
	"src_pod_template_hash",
	"src_pod_uid",
	"src_port",
	"src_replicaset",
	"src_revision",
	"src_revision_source",
	"src_service_account",
	"src_workload_kind",
	"src_workload_name",
	"src_workload_uid",
	"start_time",
	"syn_count",
	"tcp_flags_all",
	"tcp_flags_available",
	"tcp_flags_in",
	"tcp_flags_out",
	"tcp_metrics_available",
	"tcp_state",
	"tcp_window_available",
	"tcp_window_max_in",
	"tcp_window_max_out",
	"throughput_bps_in",
	"throughput_bps_out",
	"tls_parse_status",
	"tls_record_size_histogram",
	"tls_server_parse_status",
	"tls_version",
	"tls_version_negotiated",
	"traffic_accounting_available",
	"visibility_degraded",
	"visibility_degraded_reason",
	"window_id",
	"window_invalid_reason",
	"window_start_time",
	"window_valid",
}

// v1alpha5AddedKeys is the complete, closed list of what the per-direction
// split is allowed to add. Anything present in the marshalled Record but in
// neither list — or any v1alpha4 key that has gone missing — fails.
var v1alpha5AddedKeys = []string{
	"pkt_size_histogram_out",
	"pkt_size_histogram_in",
	"iat_histogram_out",
	"iat_histogram_in",
	"ip_ttl_min_out",
	"ip_ttl_max_out",
	"ip_ttl_min_in",
	"ip_ttl_max_in",
	"syn_count_out",
	"syn_count_in",
	"fin_count_out",
	"fin_count_in",
	"rst_count_out",
	"rst_count_in",
}

// TestSchemaDeltaIsAdditiveOnly is the machine check behind the v1alpha5 red
// line "additions only". It compares the marshalled Record's key set against
// the corpus-derived v1alpha4 surface and permits exactly the 14 documented
// additions: no renames, no removals, no accidental extras.
func TestSchemaDeltaIsAdditiveOnly(t *testing.T) {
	blob, err := json.Marshal(Record{})
	if err != nil {
		t.Fatalf("marshal Record: %v", err)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(blob, &decoded); err != nil {
		t.Fatalf("unmarshal Record: %v", err)
	}

	got := map[string]bool{}
	for k := range decoded {
		got[k] = true
	}

	allowed := map[string]bool{}
	for _, k := range v1alpha4RecordKeys {
		allowed[k] = true
	}
	for _, k := range v1alpha5AddedKeys {
		if allowed[k] {
			t.Fatalf("%q is listed as a v1alpha5 addition but already exists in v1alpha4", k)
		}
		allowed[k] = true
	}

	var missing, unexpected []string
	for _, k := range v1alpha4RecordKeys {
		if !got[k] {
			missing = append(missing, k)
		}
	}
	for k := range got {
		if !allowed[k] {
			unexpected = append(unexpected, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(unexpected)
	if len(missing) > 0 {
		t.Errorf("v1alpha4 keys removed or renamed: %v", missing)
	}
	if len(unexpected) > 0 {
		t.Errorf("undocumented new keys (every addition must be declared): %v", unexpected)
	}
	for _, k := range v1alpha5AddedKeys {
		if !got[k] {
			t.Errorf("declared v1alpha5 key %q is not emitted by Record", k)
		}
	}
}

// The schema version must advance exactly one step, and the record must carry
// it. A stale version on new fields is worse than no version at all.
func TestSchemaVersionIsV1Alpha5(t *testing.T) {
	if features.SchemaVersion != "v1alpha5" {
		t.Fatalf("SchemaVersion = %q, want v1alpha5", features.SchemaVersion)
	}
}
