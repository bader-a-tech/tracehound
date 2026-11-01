use tracehound_eval::process::{EndpointOwner, ProcessIdentity, ProcessSnapshot, Transport};

fn owner(pid: u32, local: &str, remote: Option<&str>) -> EndpointOwner {
    EndpointOwner {
        transport: if remote.is_some() {
            Transport::Tcp
        } else {
            Transport::Udp
        },
        local: local.parse().unwrap(),
        remote: remote.map(|address| address.parse().unwrap()),
        process: ProcessIdentity {
            pid,
            created_filetime: Some(u64::from(pid) * 100),
            executable: Some(format!("process-{pid}")),
        },
    }
}
fn snapshot(endpoints: Vec<EndpointOwner>) -> ProcessSnapshot {
    ProcessSnapshot {
        sampled_at_ms: 1000,
        completed_at_ms: 1010,
        endpoints,
        warnings: Vec::new(),
    }
}

#[test]
fn offline_old_and_future_observations_never_receive_a_pid() {
    let snapshot = snapshot(vec![owner(42, "127.0.0.1:51000", Some("127.0.0.1:443"))]);
    let src = "127.0.0.1:51000".parse().unwrap();
    let dst = "127.0.0.1:443".parse().unwrap();
    assert!(snapshot
        .associate(false, Transport::Tcp, src, dst, 1100, 2000)
        .is_empty());
    assert!(snapshot
        .associate(true, Transport::Tcp, src, dst, 1005, 2000)
        .is_empty());
    assert!(snapshot
        .associate(true, Transport::Tcp, src, dst, 5000, 2000)
        .is_empty());
    let associated = snapshot.associate(true, Transport::Tcp, src, dst, 1100, 2000);
    assert_eq!(associated.len(), 1);
    assert_eq!(associated[0].process.pid, 42);
    assert_eq!(associated[0].process.created_filetime, Some(4200));
    assert_eq!(associated[0].match_scope, "tcp_connection");
    assert!(snapshot
        .associate(
            true,
            Transport::Tcp,
            src,
            "127.0.0.1:444".parse().unwrap(),
            1100,
            2000
        )
        .is_empty());
}

#[test]
fn udp_shared_bind_is_ambiguous_and_specific_interface_beats_wildcard() {
    let src = "127.0.0.1:51000".parse().unwrap();
    let dst = "192.0.2.1:53".parse().unwrap();
    let ambiguous = snapshot(vec![
        owner(1, "0.0.0.0:51000", None),
        owner(2, "0.0.0.0:51000", None),
    ]);
    assert!(ambiguous
        .associate(true, Transport::Udp, src, dst, 1100, 2000)
        .is_empty());
    let specific = snapshot(vec![
        owner(1, "0.0.0.0:51000", None),
        owner(2, "127.0.0.1:51000", None),
        owner(3, "[::]:51000", None),
    ]);
    let result = specific.associate(true, Transport::Udp, src, dst, 1100, 2000);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].process.pid, 2);
    assert_eq!(result[0].match_scope, "udp_local_bind");
}

#[test]
fn pid_reuse_has_distinct_process_identity() {
    let first = ProcessIdentity {
        pid: 7,
        created_filetime: Some(100),
        executable: None,
    };
    let reused = ProcessIdentity {
        pid: 7,
        created_filetime: Some(200),
        executable: None,
    };
    assert_ne!(first, reused);
}

#[cfg(windows)]
#[test]
fn windows_ip_helper_identifies_this_tests_own_tcp_and_udp_sockets() {
    use std::net::{TcpListener, TcpStream, UdpSocket};
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (_server, _peer) = listener.accept().unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let table = tracehound_eval::process::snapshot().unwrap();
    let tcp = table
        .endpoints
        .iter()
        .find(|entry| {
            entry.transport == Transport::Tcp && entry.local == client.local_addr().unwrap()
        })
        .unwrap();
    assert_eq!(tcp.process.pid, std::process::id());
    assert!(tcp.process.created_filetime.is_some());
    assert!(tcp
        .process
        .executable
        .as_deref()
        .is_some_and(|name| name.contains("process-")));
    let udp = table
        .endpoints
        .iter()
        .find(|entry| entry.transport == Transport::Udp && entry.local == udp.local_addr().unwrap())
        .unwrap();
    assert_eq!(udp.process.pid, std::process::id());
}

#[cfg(not(windows))]
#[test]
fn unsupported_systems_return_an_explicit_capability_error() {
    assert!(tracehound_eval::process::snapshot()
        .unwrap_err()
        .contains("Windows"));
}
