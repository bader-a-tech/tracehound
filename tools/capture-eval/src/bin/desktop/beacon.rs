//! Human-readable beacon evidence without inferring unrecorded session facts.
use eframe::egui;
use serde_json::Value;
use tracehound_eval::Alert;

#[derive(Debug, PartialEq)]
struct Explanation {
    measurements: Vec<(&'static str, String)>,
    notes: Vec<&'static str>,
}

fn count(value: &Value, name: &str) -> Option<u64> {
    value.get(name).and_then(Value::as_u64)
}

fn finite(value: &Value, name: &str) -> Option<f64> {
    value
        .get(name)
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite() && *value >= 0.0)
}

fn explanation(alert: &Alert) -> Option<Explanation> {
    if alert.rule_id != "TH-0001" {
        return None;
    }
    let mut measurements = Vec::new();
    let evidence = &alert.evidence;
    let qualified = count(evidence, "qualifying_sessions");
    if let Some(count) = qualified {
        measurements.push(("Starts with outbound payload", count.to_string()));
    } else if let Some(count) = count(evidence, "connections") {
        measurements.push(("Reported starts", count.to_string()));
    }
    for (key, label) in [
        ("connection_attempts", "Observed session starts"),
        (
            "control_only_sessions",
            "Starts without application payload",
        ),
        (
            "inbound_only_payload_sessions",
            "Starts with inbound payload only",
        ),
        (
            "response_observed_sessions",
            "Sessions with response packets",
        ),
        (
            "bidirectional_payload_sessions",
            "Sessions with payload in both directions",
        ),
        ("tcp_syn_ack_sessions", "Sessions with SYN-ACK observed"),
        (
            "unclassified_sessions",
            "Sessions without recognized payload markers",
        ),
        ("measured_intervals", "Timing intervals measured"),
    ] {
        if let Some(count) = count(evidence, key) {
            measurements.push((label, count.to_string()));
        }
    }
    if let Some(seconds) = finite(evidence, "interval_mean_s") {
        measurements.push(("Mean start interval", format!("{seconds:.3} seconds")));
    }
    if let Some(seconds) = finite(evidence, "interval_median_s") {
        measurements.push(("Median start interval", format!("{seconds:.3} seconds")));
    }
    if let Some(cv) = finite(evidence, "interval_cv").filter(|value| (value * 100.0).is_finite()) {
        measurements.push(("Interval variation (CV)", format!("{:.1}%", cv * 100.0)));
    }
    if let Some(bytes) = finite(evidence, "mean_payload_bytes_to_server") {
        measurements.push(("Mean outbound payload", format!("{bytes:.1} bytes")));
    }
    let transport = evidence
        .get("transport")
        .and_then(Value::as_str)
        .filter(|transport| matches!(*transport, "tcp" | "udp"))
        .map(str::to_uppercase)
        .or_else(|| {
            count(evidence, "ip_protocol")
                .and_then(|protocol| u8::try_from(protocol).ok())
                .map(|protocol| match protocol {
                    6 => "TCP".into(),
                    17 => "UDP".into(),
                    number => format!("IP protocol {number}"),
                })
        });
    if let Some(transport) = transport {
        measurements.push(("Transport", transport));
    }
    let protocol_context = evidence.get("protocol_context").and_then(Value::as_object);
    if let Some(protocols) = protocol_context {
        let mut markers = Vec::new();
        for (protocol, value) in protocols.iter().take(8) {
            if let Some(count) = value.as_u64().filter(|count| *count > 0) {
                let name = match protocol.as_str() {
                    "bittorrent_peer" => "BitTorrent peer-handshake prefix".into(),
                    "dns_query" => "DNS query".into(),
                    "http_request" => "HTTP request".into(),
                    "tls_client_hello" => "TLS ClientHello".into(),
                    _ => protocol.chars().take(80).collect::<String>(),
                };
                markers.push(format!("{name}: {count}"));
            }
        }
        if !markers.is_empty() {
            measurements.push(("Captured payload markers", markers.join("; ")));
        }
    }
    if let Some(score) = alert.score.filter(|value| value.is_finite()) {
        measurements.push(("Heuristic score", format!("{score:.3}")));
    }
    let mut notes = vec![
        "Regular timing describes a traffic pattern. Peer-to-peer clients, connection retries and scheduled services can also be periodic.",
    ];
    if alert.score.is_some_and(|score| score.is_finite()) {
        notes.push(
            "The detector score is a heuristic, not the probability that a host is infected.",
        );
    }
    if evidence.get("session_confirmation").and_then(Value::as_str)
        == Some("observed_outbound_payload")
    {
        notes.push("Timing uses starts with captured outbound payload. This does not confirm that a connection or application exchange completed.");
    } else {
        notes.push("Session support was not recorded in this report. Reported starts do not establish successful sessions.");
    }
    if protocol_context.is_none() {
        notes.push("Application-protocol context was not recorded. Ports alone do not identify a protocol.");
    } else {
        notes.push("Payload marker counts are per session and may overlap. Recognized protocols do not establish that traffic is benign.");
        if protocol_context
            .and_then(|protocols| protocols.get("bittorrent_peer"))
            .and_then(Value::as_u64)
            .is_some_and(|count| count > 0)
        {
            notes.push("A BitTorrent peer-handshake prefix is observed in one direction; it does not confirm a complete peer exchange or classify other traffic to the same endpoint.");
        }
    }
    Some(Explanation {
        measurements,
        notes,
    })
}

pub fn show(ui: &mut egui::Ui, alert: &Alert) {
    let Some(explanation) = explanation(alert) else {
        return;
    };
    ui.group(|ui| {
        ui.strong("Connection pattern and supporting context");
        for (label, value) in explanation.measurements {
            ui.horizontal_wrapped(|ui| {
                ui.strong(label);
                ui.label(value);
            });
        }
        for note in explanation.notes {
            ui.small(note);
        }
    });
}

fn policy_explanation(stats: &Value) -> Option<Explanation> {
    let fields = [
        (
            "beacon_retained_groups",
            "Currently retained endpoint groups",
        ),
        (
            "beacon_retained_sessions",
            "Currently retained session starts",
        ),
        (
            "beacon_qualifying_sessions",
            "Payload-supported starts at last scoring",
        ),
        (
            "beacon_control_only_sessions",
            "Starts without application payload at last scoring",
        ),
        (
            "beacon_inbound_only_payload_sessions",
            "Starts with inbound payload only at last scoring",
        ),
        (
            "beacon_insufficient_payload_groups",
            "Groups below the payload-session minimum",
        ),
        (
            "beacon_insufficient_interval_groups",
            "Groups below the timing-interval minimum",
        ),
        (
            "beacon_syn_retransmissions_ignored",
            "Repeated SYNs ignored (cumulative)",
        ),
        (
            "beacon_sessions_dropped",
            "Starts dropped at tracking limits (cumulative)",
        ),
    ];
    let has_scoring_snapshot = count(stats, "beacon_scoring_timestamp_ms").is_some();
    let measurements = fields
        .into_iter()
        .filter(|(key, _)| {
            has_scoring_snapshot
                || matches!(
                    *key,
                    "beacon_retained_groups"
                        | "beacon_retained_sessions"
                        | "beacon_syn_retransmissions_ignored"
                        | "beacon_sessions_dropped"
                )
        })
        .filter_map(|(key, label)| count(stats, key).map(|count| (label, count.to_string())))
        .collect::<Vec<_>>();
    if measurements.is_empty() {
        return None;
    }
    Some(Explanation{measurements,notes:vec![
        "Starts without captured outbound payload are excluded from beacon timing. Exclusion is not a benign verdict; review other findings and original traffic.",
        "Scoring counts describe retained tracking state at the latest scoring tick. Retransmission and tracking-limit counters cover the analysis so far, rather than only the displayed scoring window.",
    ]})
}

pub fn show_analysis_context(ui: &mut egui::Ui, stats: &Value) {
    let Some(explanation) = policy_explanation(stats) else {
        return;
    };
    if let (Some(qualified), Some(control), Some(inbound_only), Some(_)) = (
        count(stats, "beacon_qualifying_sessions"),
        count(stats, "beacon_control_only_sessions"),
        count(stats, "beacon_inbound_only_payload_sessions"),
        count(stats, "beacon_scoring_timestamp_ms"),
    ) {
        ui.small(format!("Beacon timing at last scoring: {qualified} starts with outbound payload; {control} starts without application payload and {inbound_only} starts with inbound payload only excluded."));
    }
    ui.collapsing("Beacon timing eligibility", |ui| {
        for (label, value) in explanation.measurements {
            ui.horizontal_wrapped(|ui| {
                ui.strong(label);
                ui.label(value);
            });
        }
        if let Some(timestamp) = count(stats, "beacon_scoring_timestamp_ms") {
            let formatted = timestamp
                .checked_mul(1_000_000)
                .map(|nanos| {
                    let mut formatted = tracehound_eval::case_export::format_timestamp_ns(nanos);
                    formatted.truncate(23);
                    formatted.push_str(" UTC");
                    formatted
                })
                .unwrap_or_else(|| format!("{timestamp} capture milliseconds"));
            ui.small(format!("Scoring snapshot capture timestamp: {formatted}"));
        } else {
            ui.small("No scoring snapshot timestamp was recorded in this view.");
        }
        for note in explanation.notes {
            ui.small(note);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn alert(rule: &str, evidence: serde_json::Value) -> Alert {
        serde_json::from_value(json!({"rule_id":rule,"severity":"medium","score":0.91,"src":"10.0.0.5","evidence":evidence})).unwrap()
    }

    #[test]
    fn older_timing_reports_do_not_invent_session_or_protocol_confirmation() {
        let explanation = explanation(&alert(
            "TH-0001",
            json!({"connections":8,"interval_mean_s":60.0,"interval_cv":0.05,"dst_port":443}),
        ))
        .unwrap();
        assert!(explanation
            .measurements
            .contains(&("Reported starts", "8".into())));
        assert!(explanation
            .measurements
            .contains(&("Mean start interval", "60.000 seconds".into())));
        assert!(explanation
            .measurements
            .contains(&("Interval variation (CV)", "5.0%".into())));
        assert!(explanation
            .notes
            .iter()
            .any(|note| note.contains("not recorded")));
        assert!(!explanation
            .measurements
            .iter()
            .any(|(_, value)| value.contains("TLS") || value.contains("established")));
    }

    #[test]
    fn malformed_measurements_remain_unknown_and_other_rules_keep_their_own_context() {
        let explanation = explanation(&alert(
            "TH-0001",
            json!({"connections":"eight","interval_mean_s":-1,"interval_cv":null}),
        ))
        .unwrap();
        assert_eq!(
            explanation.measurements,
            vec![("Heuristic score", "0.910".into())]
        );
        assert!(super::explanation(&alert("TH-0002", json!({}))).is_none());
    }

    #[test]
    fn payload_support_and_directional_markers_keep_their_qualifications() {
        let explanation=explanation(&alert("TH-0001",json!({
            "ip_protocol":6,"connections":8,"connection_attempts":14,"qualifying_sessions":8,
            "control_only_sessions":4,"inbound_only_payload_sessions":2,"response_observed_sessions":6,"bidirectional_payload_sessions":3,
            "tcp_syn_ack_sessions":5,"unclassified_sessions":2,"measured_intervals":7,
            "session_confirmation":"observed_outbound_payload",
            "protocol_context":{"bittorrent_peer":3,"tls_client_hello":4},"interval_median_s":30.0
        }))).unwrap();
        assert!(explanation
            .measurements
            .contains(&("Starts with outbound payload", "8".into())));
        assert!(explanation
            .measurements
            .contains(&("Starts without application payload", "4".into())));
        assert!(explanation
            .measurements
            .contains(&("Starts with inbound payload only", "2".into())));
        assert!(explanation
            .measurements
            .contains(&("Transport", "TCP".into())));
        assert!(!explanation
            .measurements
            .iter()
            .any(|(label, _)| *label == "Reported starts"));
        assert!(explanation
            .notes
            .iter()
            .any(|note| note.contains("does not confirm a complete peer exchange")));
        assert!(explanation
            .notes
            .iter()
            .any(|note| note.contains("does not confirm that a connection")));
        assert!(!explanation
            .notes
            .iter()
            .any(|note| note.contains("was not recorded")));
    }

    #[test]
    fn eligibility_counts_keep_snapshot_and_cumulative_units_and_legacy_unknowns() {
        assert!(policy_explanation(&json!({"packets":100})).is_none());
        let explanation=policy_explanation(&json!({"beacon_retained_groups":3,"beacon_retained_sessions":14,"beacon_qualifying_sessions":8,"beacon_control_only_sessions":4,"beacon_inbound_only_payload_sessions":2,"beacon_insufficient_payload_groups":2,"beacon_syn_retransmissions_ignored":19,"beacon_sessions_dropped":0,"beacon_scoring_timestamp_ms":1_700_000_000_000_u64})).unwrap();
        assert!(explanation.measurements.contains(&(
            "Starts without application payload at last scoring",
            "4".into()
        )));
        assert!(explanation.measurements.contains(&(
            "Starts with inbound payload only at last scoring",
            "2".into()
        )));
        assert!(explanation
            .measurements
            .contains(&("Repeated SYNs ignored (cumulative)", "19".into())));
        assert!(explanation
            .notes
            .iter()
            .any(|note| note.contains("not a benign verdict")));
        let before_scoring = policy_explanation(&json!({
            "beacon_retained_sessions":3,"beacon_qualifying_sessions":0,
            "beacon_control_only_sessions":0,"beacon_inbound_only_payload_sessions":0,
            "beacon_scoring_timestamp_ms":null
        }))
        .unwrap();
        assert_eq!(
            before_scoring.measurements,
            vec![("Currently retained session starts", "3".into())]
        );
    }
}
