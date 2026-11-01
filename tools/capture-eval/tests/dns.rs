use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tracehound_eval::{capture::DnsObservation, dns::DnsPolicy, Severity};

#[test]
fn incremental_dns_keeps_working_after_the_offline_observation_limit() {
    use tracehound_eval::{capture::PacketRef, dns::DnsAnalyzer};
    let mut analyzer = DnsAnalyzer::new(DnsPolicy::load(None).unwrap());
    for index in 0..50_010 {
        let query = DnsObservation {
            src: "10.1.2.3".parse().unwrap(),
            dst: "192.0.2.53".parse().unwrap(),
            name: "www.example.com".into(),
            query_type: 1,
            timestamp_ms: index,
            ..Default::default()
        };
        assert!(analyzer.observe(&query).is_empty());
    }
    let mut alerts = Vec::new();
    for (index, mut query) in queries("attacker.net", 45, 60_000, 1000)
        .into_iter()
        .enumerate()
    {
        query.packets = vec![PacketRef {
            number: 50_011 + index as u64,
            timestamp_ns: query.timestamp_ms * 1_000_000,
            ..Default::default()
        }];
        alerts.extend(analyzer.observe(&query));
    }
    alerts.extend(analyzer.tick(110_000));
    assert!(alerts
        .iter()
        .any(|alert| alert.evidence["domain"] == "attacker.net"));
    let finding = alerts
        .iter()
        .find(|alert| alert.evidence["domain"] == "attacker.net")
        .unwrap();
    assert!(!finding.extra["packets"].as_array().unwrap().is_empty());
    assert!(finding.extra["window_start_ms"].as_u64().unwrap() >= 60_000);
    analyzer.tick(4_000_000);
    assert_eq!(analyzer.tracked_domains(), 0);
    let late = queries("attacker.net", 1, 1000, 1000).remove(0);
    assert!(analyzer.observe(&late).is_empty());
    assert_eq!(analyzer.dropped_out_of_order, 1);
}

#[test]
fn global_name_budget_is_bounded_disclosed_and_reclaimed_after_expiry() {
    use tracehound_eval::dns::DnsAnalyzer;
    let rules = Rules::new(&rule("tuning:\n  min_queries: 3\n  history: 1s\n"));
    let mut analyzer = DnsAnalyzer::with_name_budget(rules.load().unwrap(), 4).unwrap();
    let mut alerts = Vec::new();
    for query in queries("alpha.example.com", 12, 1000, 10)
        .into_iter()
        .chain(queries("beta.example.net", 12, 1200, 10))
    {
        alerts.extend(analyzer.observe(&query));
        assert!(analyzer.retained_names() <= 4);
    }
    alerts.extend(analyzer.tick(1500));
    // The configured score interval need not have elapsed; finish uses exactly
    // the same retained state and reports the uncertainty from dropped names.
    assert!(analyzer.dropped_name_events >= 20);
    analyzer.tick(40_000);
    assert_eq!(analyzer.retained_names(), 0);
    let later = queries("later.example.org", 6, 41_000, 10);
    for query in &later {
        alerts.extend(analyzer.observe(query));
        assert!(analyzer.retained_names() <= 4);
    }
    alerts.extend(analyzer.finish());
    assert!(alerts
        .iter()
        .any(|alert| alert.evidence["name_retention_limited"] == true
            && alert.evidence["unique_ratio_is_lower_bound"] == true));
}

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct Rules(PathBuf);
impl Rules {
    fn new(body: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tracehound-dns-{}-{unique}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("policy.yaml"), body).unwrap();
        Self(root)
    }
    fn load(&self) -> Result<DnsPolicy, String> {
        DnsPolicy::load(Some(&self.0))
    }
}
impl Drop for Rules {
    fn drop(&mut self) {
        // Remove only this test's exact file and empty directory.
        let _ = fs::remove_file(self.0.join("policy.yaml"));
        let _ = fs::remove_dir(&self.0);
    }
}

fn queries(domain: &str, count: usize, start: u64, step: u64) -> Vec<DnsObservation> {
    (0..count)
        .map(|i| DnsObservation {
            src: "10.1.2.3".parse().unwrap(),
            dst: "192.0.2.53".parse().unwrap(),
            name: format!("{i:04x}abcdefghijklmnopqrstuvwxyz0123456789abcdefghij.{domain}"),
            query_type: 16,
            timestamp_ms: start + i as u64 * step,
            ..Default::default()
        })
        .collect()
}
fn rule(extra: &str) -> String {
    format!("id: TH-0002\nname: DNS\ndetector: dns-tunnel\n{extra}")
}

#[test]
fn builtin_scores_real_queries_and_separates_private_psl_tenants() {
    let policy = DnsPolicy::load(None).unwrap();
    assert!(policy.enabled);
    let mut data = queries("alpha.blogspot.com", 40, 1_000, 1_000);
    data.extend(queries("beta.blogspot.com", 40, 1_000, 1_000));
    data.reverse(); // Merged captures may step backwards; scoring orders by time.
    let alerts = policy.detect(&data);
    assert_eq!(alerts.len(), 2);
    let domains: Vec<_> = alerts
        .iter()
        .map(|a| a.evidence["domain"].as_str().unwrap())
        .collect();
    assert_eq!(domains, ["alpha.blogspot.com", "beta.blogspot.com"]);
    for alert in alerts {
        assert_eq!(alert.rule_id, "TH-0002");
        assert_eq!(alert.severity, Severity::High);
        assert_eq!(alert.score, Some(1.0));
        assert!(alert.evidence["queries"].as_u64().unwrap() >= 30);
        assert_eq!(alert.evidence["unique_ratio"], 1.0);
        assert_eq!(alert.extra["dst_port"], 53);
    }
}

#[test]
fn psl_wildcard_exception_keeps_city_domain_together() {
    let alerts = DnsPolicy::load(None)
        .unwrap()
        .detect(&queries("city.kawasaki.jp", 35, 0, 1_000));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].evidence["domain"], "city.kawasaki.jp");
}

#[test]
fn legitimate_repeated_short_a_queries_do_not_alert() {
    let mut data = queries("example.com", 100, 0, 1_000);
    for query in &mut data {
        query.name = "www.example.com".into();
        query.query_type = 1;
    }
    assert!(DnsPolicy::load(None).unwrap().detect(&data).is_empty());
}

#[test]
fn shipped_raw_name_exceptions_survive_psl_grouping() {
    let policy = DnsPolicy::load(None).unwrap();
    for name in ["avts.mcafee.com", "zen.spamhaus.org"] {
        assert!(
            policy.detect(&queries(name, 80, 0, 1_000)).is_empty(),
            "{name}"
        );
    }
}

#[test]
fn custom_yaml_controls_tuning_metadata_and_missing_or_disabled_rule() {
    let custom = Rules::new(&rule(concat!(
        "severity: critical\n",
        "techniques:\n  - id: T0000\n    name: Local mapping\n    tactic: discovery\n",
        "tuning:\n  min_queries: 4\n  threshold: 0.8\n  history: 1h30m\n"
    )));
    let policy = custom.load().unwrap();
    let alerts = policy.detect(&queries("example.com", 4, 0, 1_000));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].severity, Severity::Critical);
    assert_eq!(alerts[0].extra["techniques"][0]["id"], "T0000");
    let disabled = Rules::new(&rule("enabled: false\n"));
    assert!(!disabled.load().unwrap().enabled);
    assert!(disabled
        .load()
        .unwrap()
        .detect(&queries("example.com", 100, 0, 1_000))
        .is_empty());
    let missing = Rules::new("id: TH-0001\nname: Beacon\ndetector: beaconing\n");
    assert!(!missing.load().unwrap().enabled);
}

#[test]
fn exception_conditions_are_anded_and_ja4_does_not_match_udp_dns() {
    let custom = Rules::new(&rule(concat!(
        "exceptions:\n  - description: Scoped exemption\n    src: 10.0.0.0/8\n    dst: 192.0.2.0/24\n    dst_port: 53\n    domain: .example.com\n",
        "  - description: TLS-only exemption\n    domain: other.com\n    ja4: t13anything\n",
        "  - description: Different port\n    domain: ports.com\n    dst_port: 443\n"
    )));
    let policy = custom.load().unwrap();
    assert!(policy
        .detect(&queries("example.com", 40, 0, 1_000))
        .is_empty());
    let mut outside = queries("example.com", 40, 0, 1_000);
    for q in &mut outside {
        q.src = "172.16.2.3".parse().unwrap();
    }
    assert_eq!(policy.detect(&outside).len(), 1);
    assert_eq!(policy.detect(&queries("other.com", 40, 0, 1_000)).len(), 1);
    assert_eq!(policy.detect(&queries("ports.com", 40, 0, 1_000)).len(), 1);
}

#[test]
fn expired_burst_does_not_supply_minimum_queries_for_later_traffic() {
    let custom = Rules::new(&rule("tuning:\n  min_queries: 30\n  history: 60s\n"));
    let mut data = queries("example.com", 20, 0, 1_000);
    data.extend(queries("example.com", 20, 120_000, 1_000));
    assert!(custom.load().unwrap().detect(&data).is_empty());
}

#[test]
fn cooldown_requires_changed_evidence_and_allows_severity_escalation() {
    let policy = DnsPolicy::load(None).unwrap();
    let mut data = queries("example.com", 1_100, 0, 1_000);
    let alerts = policy.detect(&data);
    assert_eq!(alerts.len(), 2);
    assert!(
        alerts[1].extra["capture_timestamp_ms"].as_u64().unwrap()
            - alerts[0].extra["capture_timestamp_ms"].as_u64().unwrap()
            >= 600_000
    );
    // A query to another domain advances capture time but cannot manufacture
    // new evidence or a restatement for the original completed burst.
    data.truncate(40);
    data.extend(queries("benign.example.net", 1, 700_000, 1));
    data.extend(queries("benign.example.net", 1, 1_400_000, 1));
    assert_eq!(policy.detect(&data).len(), 2); // one changed final burst update after cooldown.
}

#[test]
fn severity_escalates_before_the_cooldown_expires() {
    let mut data = queries("example.com", 30, 0, 1_000);
    for query in &mut data {
        let label = query.name.split('.').next().unwrap()[..45].to_string();
        query.name = format!("{label}.example.com");
        query.query_type = 1;
    }
    data.extend(queries("example.com", 100, 30_000, 1_000));
    let alerts = DnsPolicy::load(None).unwrap().detect(&data);
    assert_eq!(alerts.len(), 2);
    assert_eq!(alerts[0].severity, Severity::Medium);
    assert_eq!(alerts[1].severity, Severity::High);
    assert!(alerts[1].extra["capture_timestamp_ms"].as_u64().unwrap() < 600_000);
}

#[test]
fn invalid_policy_fails_instead_of_silently_ignoring_operator_intent() {
    for extra in [
        "tuning:\n  threshhold: 0.9\n",
        "tuning:\n  threshold: 1.5\n",
        "tuning:\n  history: 6 hours\n",
        "tuning:\n  history: -1h\n",
        "exceptions:\n  - description: Missing match\n",
        "exceptions:\n  - description: Bad network\n    src: 10.0.0.1/99\n",
        "severity: catastrophic\n",
    ] {
        assert!(Rules::new(&rule(extra)).load().is_err(), "{extra}");
    }
    let duplicate = format!("{}---\n{}", rule(""), rule(""));
    assert!(Rules::new(&duplicate).load().is_err());
}

#[test]
fn unique_name_and_track_caps_are_enforced() {
    let custom = Rules::new(&rule("tuning:\n  max_unique_names: 3\n  max_tracked: 1\n"));
    let mut data = queries("first.example.com", 40, 0, 1_000);
    data.extend(queries("second.example.net", 40, 0, 1_000));
    data.sort_by_key(|query| query.timestamp_ms);
    let mut analyzer = tracehound_eval::dns::DnsAnalyzer::new(custom.load().unwrap());
    let mut alerts = Vec::new();
    for query in &data {
        alerts.extend(analyzer.observe(query));
    }
    assert_eq!(analyzer.tracked_domains(), 1);
    assert_eq!(analyzer.retained_names(), 3);
    assert!(analyzer.dropped_track_events > 0);
    assert!(analyzer.dropped_name_events > 0);
    alerts.extend(analyzer.flush());
    assert!(alerts.is_empty());
    assert!(analyzer.uncertainty_limited_scores > 0);
}

#[test]
fn name_limits_cannot_manufacture_tunnel_alerts_from_repeated_names() {
    use tracehound_eval::dns::DnsAnalyzer;
    let rules = Rules::new(&rule("tuning:\n  max_unique_names: 2\n"));
    let mut analyzer = DnsAnalyzer::new(rules.load().unwrap());
    for index in 0..103u64 {
        let mut query = queries("repeated.example.net", 1, index * 1000, 1).remove(0);
        let label = if index == 0 {
            "a"
        } else if index == 1 {
            "b"
        } else {
            "c"
        };
        query.name = format!(
            "{label}abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmn.repeated.example.net"
        );
        query.query_type = 1;
        assert!(analyzer.observe(&query).is_empty());
    }
    assert!(analyzer.flush().is_empty());
    assert!(analyzer.uncertainty_limited_scores > 0);
    let policy = Rules::new(&rule("tuning:\n  max_unique_names: 65536\n"));
    let mut global = DnsAnalyzer::with_name_budget(policy.load().unwrap(), 2).unwrap();
    for query in queries("unrelated.example.com", 2, 0, 1) {
        assert!(global.observe(&query).is_empty());
    }
    for mut query in queries("fresh.example.net", 103, 1000, 1000) {
        query.name = "cabcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmn.fresh.example.net".into();
        query.query_type = 1;
        assert!(global.observe(&query).is_empty());
    }
    assert!(global.flush().is_empty());
    assert_eq!(global.retained_names(), 2);
    assert!(global.uncertainty_limited_scores > 0);
}
