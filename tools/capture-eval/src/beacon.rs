//! Bounded, time-aligned evidence for the incremental TH-0001 detector.
//! A failed TCP opening attempt supplies no application-session timing evidence.
//! Observed protocol headers add context only; none suppress a finding.

use super::{
    alert, average, coefficient, median, round3, unmap, FlowKey, Policy, StreamLimits, StreamStats,
};
use crate::capture::{DecodeEvents, DecodedPacket, PacketRef};
use crate::{Alert, Severity};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};

// An aggregate backstop prevents the product of track and per-track limits from
// growing into millions of records. Expiry does not count as pressure loss.
pub(super) const MAX_SESSIONS: usize = 65_536;
pub(super) const MAX_SESSION_REFS: usize = 4;
type Group = (IpAddr, IpAddr, u16, u8);
type SessionKey = (u64, u64);

#[derive(Clone, Debug)]
pub(super) struct BeaconPointer {
    group: Group,
    session: SessionKey,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_session_budget_bounds_many_tracks_and_recovers_after_history_expiry() {
        let mut book = BeaconBook::default();
        let mut packet = DecodedPacket {
            flow_id: None,
            src: "10.0.0.5".parse().unwrap(),
            dst: "198.51.100.9".parse().unwrap(),
            src_port: 40_000,
            dst_port: 443,
            protocol: 6,
            tcp_flags: Some(2),
            tcp_sequence: Some(1),
            tcp_ack: None,
            timestamp_ms: 1,
            packets: Vec::new(),
            payload: Vec::new(),
            wire_bytes: 60,
            captured_bytes: 60,
        };
        for _ in 0..MAX_SESSIONS {
            assert_eq!(
                book.start(&packet, FlowKey::packet(&packet), 10, MAX_SESSIONS)
                    .1,
                0
            );
        }
        assert_eq!(book.sessions(), MAX_SESSIONS);
        packet.dst_port = 8443;
        let rejected = book.start(&packet, FlowKey::packet(&packet), 10, MAX_SESSIONS);
        assert!(rejected.0.is_none());
        assert_eq!(rejected.1, 1);
        assert_eq!(book.groups(), 1);
        packet.dst_port = 443;
        packet.timestamp_ms = 2;
        let replacement = book.start(&packet, FlowKey::packet(&packet), 10, MAX_SESSIONS);
        assert!(replacement.0.is_some());
        assert_eq!(replacement.1, 1);
        assert_eq!(book.sessions(), MAX_SESSIONS);
        let policy = Policy::load(None).unwrap();
        let mut stats = StreamStats::default();
        assert!(book
            .score(&policy, &StreamLimits::default(), 3, 3, &mut stats)
            .is_empty());
        assert_eq!(book.sessions(), 0);
        assert_eq!(book.groups(), 0);
        assert_eq!(
            book.start(&packet, FlowKey::packet(&packet), 10, MAX_SESSIONS)
                .1,
            0
        );
        assert_eq!(book.sessions(), 1);
    }
}
struct Session {
    flow: FlowKey,
    last: u64,
    wire_out: u64,
    payload_out: u64,
    payload_in: u64,
    response: bool,
    syn_ack: bool,
    protocols: BTreeSet<&'static str>,
    packets: Vec<PacketRef>,
}
#[derive(Default)]
pub(super) struct BeaconBook {
    tracks: BTreeMap<Group, BTreeMap<SessionKey, Session>>,
    retained: usize,
    next_id: u64,
}
impl BeaconBook {
    pub(super) fn groups(&self) -> usize {
        self.tracks.len()
    }
    pub(super) fn sessions(&self) -> usize {
        self.retained
    }

    pub(super) fn start(
        &mut self,
        packet: &DecodedPacket,
        flow: FlowKey,
        max_groups: usize,
        max_sessions: usize,
    ) -> (Option<BeaconPointer>, u64) {
        let group = (
            unmap(packet.src),
            unmap(packet.dst),
            packet.dst_port,
            packet.protocol,
        );
        if !self.tracks.contains_key(&group) && self.tracks.len() >= max_groups {
            return (None, 1);
        }
        let replaces_record = self
            .tracks
            .get(&group)
            .is_some_and(|track| track.len() >= max_sessions);
        if self.retained >= MAX_SESSIONS && !replaces_record {
            return (None, 1);
        }
        let session = (packet.timestamp_ms, self.next_id);
        self.next_id = self.next_id.saturating_add(1);
        self.tracks.entry(group).or_default().insert(
            session,
            Session {
                flow,
                last: packet.timestamp_ms,
                wire_out: 0,
                payload_out: 0,
                payload_in: 0,
                response: false,
                syn_ack: false,
                protocols: BTreeSet::new(),
                packets: packet.packets.iter().take(1).cloned().collect(),
            },
        );
        self.retained += 1;
        let track = self.tracks.get_mut(&group).unwrap();
        let mut dropped = 0;
        while track.len() > max_sessions {
            track.pop_first();
            self.retained -= 1;
            dropped += 1;
        }
        // Insert before eviction so a late old start cannot displace a newer
        // retained sample. Its active-flow pointer is deliberately absent.
        let pointer = track
            .contains_key(&session)
            .then_some(BeaconPointer { group, session });
        (pointer, dropped)
    }

    pub(super) fn observe(
        &mut self,
        pointer: &BeaconPointer,
        packet: &DecodedPacket,
        client: SocketAddr,
        syn_sequence: Option<u32>,
        syn_ack_expected: Option<u32>,
    ) {
        let Some(session) = self
            .tracks
            .get_mut(&pointer.group)
            .and_then(|track| track.get_mut(&pointer.session))
        else {
            return;
        };
        if packet.timestamp_ms < pointer.session.0 {
            return;
        }
        let outbound = unmap(packet.src) == unmap(client.ip()) && packet.src_port == client.port();
        let first_out_payload = outbound && !packet.payload.is_empty() && session.payload_out == 0;
        let first_in_payload = !outbound && !packet.payload.is_empty() && session.payload_in == 0;
        let first_response = !outbound && !session.response;
        let syn_ack = !outbound
            && packet.protocol == 6
            && packet.tcp_flags.is_some_and(|flags| flags & 0x17 == 0x12)
            && (syn_ack_expected.is_some_and(|expected| packet.tcp_ack == Some(expected))
                // Fast Open servers may reject SYN data and acknowledge only
                // the SYN, then receive that data after the handshake.
                || syn_sequence.is_some_and(|sequence| packet.tcp_ack == Some(sequence.wrapping_add(1))));
        session.last = session.last.max(packet.timestamp_ms);
        if outbound {
            session.wire_out = session.wire_out.saturating_add(packet.wire_bytes);
            session.payload_out = session
                .payload_out
                .saturating_add(packet.payload.len() as u64);
        } else {
            session.response = true;
            session.payload_in = session
                .payload_in
                .saturating_add(packet.payload.len() as u64);
        }
        session.syn_ack |= syn_ack;
        if first_out_payload || first_in_payload || first_response {
            for reference in &packet.packets {
                if session.packets.len() < MAX_SESSION_REFS
                    && !session.packets.iter().any(|stored| {
                        stored.number == reference.number
                            && stored.section == reference.section
                            && stored.interface == reference.interface
                    })
                {
                    session.packets.push(reference.clone());
                }
            }
        }
    }

    pub(super) fn annotate_events(&mut self, events: &DecodeEvents) {
        for observation in &events.http {
            self.annotate(
                observation.src,
                observation.dst,
                observation.src_port,
                observation.dst_port,
                6,
                observation.timestamp_ms,
                &observation.packets,
                "http_request",
            );
        }
        for observation in &events.tls_clients {
            self.annotate(
                observation.src,
                observation.dst,
                observation.src_port,
                observation.dst_port,
                6,
                observation.timestamp_ms,
                &observation.packets,
                "tls_client_hello",
            );
        }
        for observation in &events.dns {
            // DnsObservation currently comes only from the UDP decoder.
            self.annotate(
                observation.src,
                observation.dst,
                observation.src_port,
                observation.dst_port,
                17,
                observation.timestamp_ms,
                &observation.packets,
                "dns_query",
            );
        }
        for observation in &events.peer_protocols {
            if observation.protocol == "bittorrent_peer" && observation.handshake_bytes == 68 {
                self.annotate(
                    observation.src,
                    observation.dst,
                    observation.src_port,
                    observation.dst_port,
                    6,
                    observation.timestamp_ms,
                    &observation.packets,
                    "bittorrent_peer",
                );
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn annotate(
        &mut self,
        src: IpAddr,
        dst: IpAddr,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
        at: u64,
        references: &[PacketRef],
        marker: &'static str,
    ) {
        let src = unmap(src);
        let dst = unmap(dst);
        let first = SocketAddr::new(src, src_port);
        let second = SocketAddr::new(dst, dst_port);
        let reference = references.first();
        let flow = FlowKey {
            section: reference.map_or(0, |r| r.section),
            interface: reference.map_or(0, |r| r.interface),
            first: first.min(second),
            second: first.max(second),
            protocol,
        };
        for group in [
            (src, dst, dst_port, protocol),
            (dst, src, src_port, protocol),
        ] {
            if let Some(track) = self.tracks.get_mut(&group) {
                // Reused tuples must not inherit an earlier session's marker.
                if let Some((_, session)) = track.iter_mut().rev().find(|((start, _), session)| {
                    *start <= at && session.last >= at && session.flow == flow
                }) {
                    session.protocols.insert(marker);
                }
            }
        }
    }

    pub(super) fn score(
        &mut self,
        policy: &Policy,
        limits: &StreamLimits,
        cutoff: u64,
        now: u64,
        stats: &mut StreamStats,
    ) -> Vec<(Alert, Vec<PacketRef>)> {
        self.tracks.retain(|_, track| {
            let before = track.len();
            track.retain(|(start, _), _| *start >= cutoff);
            self.retained -= before - track.len();
            !track.is_empty()
        });
        stats.beacon_scoring_timestamp_ms = Some(now);
        stats.beacon_qualifying_sessions = 0;
        stats.beacon_control_only_sessions = 0;
        stats.beacon_inbound_only_payload_sessions = 0;
        stats.beacon_insufficient_payload_groups = 0;
        stats.beacon_insufficient_interval_groups = 0;
        let minimum = policy.count("beaconing", "min_connections", 8);
        let mut hits = Vec::new();
        for ((src, dst, port, protocol), track) in &self.tracks {
            let sessions = track
                .iter()
                .filter(|(_, session)| session.payload_out > 0)
                .collect::<Vec<_>>();
            let control_only = track
                .values()
                .filter(|session| session.payload_out == 0 && session.payload_in == 0)
                .count();
            let inbound_only = track
                .values()
                .filter(|session| session.payload_out == 0 && session.payload_in > 0)
                .count();
            stats.beacon_qualifying_sessions += sessions.len();
            stats.beacon_control_only_sessions += control_only;
            stats.beacon_inbound_only_payload_sessions += inbound_only;
            if sessions.len() < minimum {
                if track.len() >= minimum {
                    stats.beacon_insufficient_payload_groups += 1;
                }
                continue;
            }
            let intervals = sessions
                .windows(2)
                .filter(|pair| pair[1].0 .0 > pair[0].0 .0)
                .map(|pair| (pair[1].0 .0 - pair[0].0 .0) as f64 / 1000.0)
                .collect::<Vec<_>>();
            // A burst of same-timestamp starts cannot supply the required number
            // of measured intervals merely by increasing the session count.
            if intervals.len() < minimum.saturating_sub(1).max(1) {
                stats.beacon_insufficient_interval_groups += 1;
                continue;
            }
            let mean = average(&intervals);
            if mean * 1000.0 < policy.duration("beaconing", "min_interval", 2000) as f64
                || mean * 1000.0 > policy.duration("beaconing", "max_interval", 21_600_000) as f64
            {
                continue;
            }
            let cv = coefficient(&intervals);
            let med = median(&intervals);
            let mad = median(
                &intervals
                    .iter()
                    .map(|value| (value - med).abs())
                    .collect::<Vec<_>>(),
            ) / med;
            let periodicity = 1.0 - cv.min(mad).clamp(0.0, 1.0);
            let sizes = sessions
                .iter()
                .map(|(_, session)| session.wire_out as f64)
                .collect::<Vec<_>>();
            let payloads = sessions
                .iter()
                .map(|(_, session)| session.payload_out as f64)
                .collect::<Vec<_>>();
            let size_score = if sizes.len() >= 3 {
                1.0 - coefficient(&sizes).clamp(0.0, 1.0)
            } else {
                0.5
            };
            let score = 0.75 * periodicity + 0.25 * size_score;
            if score < policy.number("beaconing", "threshold", 0.75) {
                continue;
            }
            let mut protocols = BTreeMap::<&str, usize>::new();
            for (_, session) in &sessions {
                for marker in &session.protocols {
                    *protocols.entry(marker).or_default() += 1;
                }
            }
            let mut hit = alert(
                "TH-0001",
                if score >= 0.9 && sessions.len() >= 20 {
                    Severity::High
                } else {
                    Severity::Medium
                },
                *src,
                Some(*dst),
                *port,
                "Periodic outbound beaconing",
                json!({
                    "connections":sessions.len(), "connection_attempts":track.len(), "qualifying_sessions":sessions.len(), "control_only_sessions":control_only,
                    "inbound_only_payload_sessions":inbound_only,
                    "bidirectional_payload_sessions":sessions.iter().filter(|(_, s)| s.payload_in > 0).count(),
                    "response_observed_sessions":sessions.iter().filter(|(_, s)| s.response).count(),
                    "tcp_syn_ack_sessions":sessions.iter().filter(|(_, s)| s.syn_ack).count(),
                    "unclassified_sessions":sessions.iter().filter(|(_, s)| s.protocols.is_empty()).count(),
                    "session_confirmation":"observed_outbound_payload", "protocol_context":protocols, "ip_protocol":protocol,
                    "measured_intervals":intervals.len(), "interval_mean_s":round3(mean), "interval_median_s":round3(med),
                    "interval_cv":round3(cv), "interval_mad_ratio":round3(mad), "jitter_pct":round3(cv * 100.0),
                    "periodicity_score":round3(periodicity), "size_consistency":round3(size_score),
                    "mean_bytes_to_server":round3(average(&sizes)), "mean_payload_bytes_to_server":round3(average(&payloads)),
                    "window_start_ms":sessions.first().unwrap().0.0, "window_end_ms":sessions.iter().map(|(_, s)| s.last).max().unwrap()
                }),
            );
            hit.score = Some(score);
            let references = sessions
                .iter()
                .flat_map(|(_, session)| session.packets.iter().cloned())
                .take(limits.max_evidence_packets)
                .collect::<Vec<_>>();
            hits.push((hit, references));
        }
        hits
    }
}
