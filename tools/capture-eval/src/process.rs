//! Optional local Windows endpoint ownership. Offline captures never consult
//! operating-system process tables. A table match is a sampled association,
//! not proof that a particular process generated every packet in a flow.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::SocketAddr;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Tcp,
    Udp,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProcessIdentity {
    pub pid: u32,
    /// Windows FILETIME, in 100ns intervals since 1601; distinguishes PID reuse
    /// when process-query permission is available.
    pub created_filetime: Option<u64>,
    pub executable: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EndpointOwner {
    pub transport: Transport,
    pub local: SocketAddr,
    pub remote: Option<SocketAddr>,
    pub process: ProcessIdentity,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProcessSnapshot {
    pub sampled_at_ms: u64,
    pub completed_at_ms: u64,
    pub endpoints: Vec<EndpointOwner>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProcessAssociation {
    pub process: ProcessIdentity,
    pub endpoint: SocketAddr,
    pub sampled_at_ms: u64,
    pub observation_at_ms: u64,
    /// UDP owner tables identify a local bind, without a remote endpoint.
    pub match_scope: String,
    pub source: String,
    pub identity_time_verified: bool,
}

impl ProcessSnapshot {
    /// Match only observations from this computer's current live capture.
    /// Ambiguous shared binds and stale/future snapshots produce no attribution.
    /// Callers must keep a process association per observation rather than
    /// assigning one PID to the lifetime of a reused five-tuple.
    pub fn associate(
        &self,
        local_live: bool,
        transport: Transport,
        src: SocketAddr,
        dst: SocketAddr,
        observed_at_ms: u64,
        max_age_ms: u64,
    ) -> Vec<ProcessAssociation> {
        if !local_live
            || max_age_ms > 10_000
            || self.completed_at_ms < self.sampled_at_ms
            || self.sampled_at_ms > observed_at_ms
            || self.completed_at_ms > observed_at_ms
            || observed_at_ms.saturating_sub(self.sampled_at_ms) > max_age_ms
        {
            return Vec::new();
        }
        let mut result = Vec::new();
        for (local, remote) in [(src, dst), (dst, src)] {
            let candidates = self
                .endpoints
                .iter()
                .filter(|entry| {
                    entry.transport == transport
                        && entry.local.port() == local.port()
                        && entry.local.is_ipv4() == local.is_ipv4()
                        && (entry.local.ip() == local.ip() || entry.local.ip().is_unspecified())
                        && entry.remote.is_none_or(|peer| peer == remote)
                        && entry.process.pid != 0
                })
                .collect::<Vec<_>>();
            let exact = candidates
                .iter()
                .any(|entry| !entry.local.ip().is_unspecified());
            let candidates = candidates
                .into_iter()
                .filter(|entry| !exact || !entry.local.ip().is_unspecified())
                .collect::<Vec<_>>();
            let identities = candidates
                .iter()
                .map(|entry| (entry.process.pid, entry.process.created_filetime))
                .collect::<BTreeSet<_>>();
            if identities.len() != 1 {
                continue;
            }
            if let Some(entry) = candidates.first() {
                result.push(ProcessAssociation {
                    process: entry.process.clone(),
                    endpoint: local,
                    sampled_at_ms: self.sampled_at_ms,
                    observation_at_ms: observed_at_ms,
                    match_scope: if entry.remote.is_some() {
                        "tcp_connection"
                    } else {
                        "udp_local_bind"
                    }
                    .into(),
                    source: "windows_ip_helper_snapshot".into(),
                    identity_time_verified: entry.process.created_filetime.is_some(),
                });
            }
        }
        result
    }
}

#[cfg(windows)]
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

/// Read the current computer's TCP/UDP owner tables. Does not elevate, start a
/// service, install a driver, or resolve executable names over the network.
pub fn snapshot() -> Result<ProcessSnapshot, String> {
    #[cfg(windows)]
    {
        windows::snapshot()
    }
    #[cfg(not(windows))]
    {
        Err("Local process attribution currently supports Windows IP Helper only.".into())
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::collections::BTreeMap;
    use std::ffi::c_void;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::ptr;

    const MAX_TABLE_BYTES: usize = 16 * 1024 * 1024;
    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        fn GetExtendedTcpTable(
            table: *mut c_void,
            size: *mut u32,
            order: i32,
            family: u32,
            class: u32,
            reserved: u32,
        ) -> u32;
        fn GetExtendedUdpTable(
            table: *mut c_void,
            size: *mut u32,
            order: i32,
            family: u32,
            class: u32,
            reserved: u32,
        ) -> u32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
        fn CloseHandle(handle: *mut c_void) -> i32;
        fn GetProcessTimes(
            handle: *mut c_void,
            created: *mut FileTime,
            exit: *mut FileTime,
            kernel: *mut FileTime,
            user: *mut FileTime,
        ) -> i32;
        fn QueryFullProcessImageNameW(
            handle: *mut c_void,
            flags: u32,
            name: *mut u16,
            size: *mut u32,
        ) -> i32;
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct FileTime {
        low: u32,
        high: u32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Tcp4 {
        state: u32,
        local: u32,
        local_port: u32,
        remote: u32,
        remote_port: u32,
        pid: u32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Tcp6 {
        local: [u8; 16],
        local_scope: u32,
        local_port: u32,
        remote: [u8; 16],
        remote_scope: u32,
        remote_port: u32,
        state: u32,
        pid: u32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Udp4 {
        local: u32,
        local_port: u32,
        pid: u32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Udp6 {
        local: [u8; 16],
        local_scope: u32,
        local_port: u32,
        pid: u32,
    }

    fn table(tcp: bool, family: u32) -> Result<Vec<u8>, String> {
        let mut size = 0;
        for _ in 0..4 {
            if size as usize > MAX_TABLE_BYTES {
                return Err("Windows endpoint owner table exceeds 16 MiB.".into());
            }
            let mut buffer = vec![0u32; (size as usize).div_ceil(4)];
            let pointer = if buffer.is_empty() {
                ptr::null_mut()
            } else {
                buffer.as_mut_ptr().cast()
            };
            // IP Helper accepts a caller-sized writable buffer. Vec<u32>
            // supplies DWORD alignment and the API reports the actual size.
            let status = unsafe {
                if tcp {
                    GetExtendedTcpTable(pointer, &mut size, 0, family, 5, 0)
                } else {
                    GetExtendedUdpTable(pointer, &mut size, 0, family, 1, 0)
                }
            };
            if status == 122 {
                continue;
            }
            if status != 0 {
                return Err(format!(
                    "Windows {} IPv{} table returned error {status}",
                    if tcp { "TCP" } else { "UDP" },
                    if family == 2 { 4 } else { 6 }
                ));
            }
            if size as usize > buffer.len() * 4 {
                return Err("Windows table returned an invalid length.".into());
            }
            // Copy initialized bytes only; every element was zero-initialized.
            return Ok(unsafe {
                std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), size as usize)
            }
            .to_vec());
        }
        Err("Windows endpoint owner table kept changing during sampling.".into())
    }
    fn rows<T: Copy>(bytes: &[u8]) -> Result<Vec<T>, String> {
        let count = bytes
            .get(..4)
            .ok_or("Truncated Windows endpoint owner table.")?;
        let count = u32::from_ne_bytes(count.try_into().unwrap()) as usize;
        let length = count
            .checked_mul(std::mem::size_of::<T>())
            .and_then(|n| n.checked_add(4))
            .ok_or("Windows endpoint owner table size overflow.")?;
        if length > bytes.len() {
            return Err("Truncated Windows endpoint owner rows.".into());
        }
        // All four documented owner-PID row structures contain DWORD-aligned
        // members only, so the first row follows the DWORD count at offset 4.
        Ok((0..count)
            .map(|index| unsafe {
                ptr::read_unaligned(
                    bytes
                        .as_ptr()
                        .add(4 + index * std::mem::size_of::<T>())
                        .cast::<T>(),
                )
            })
            .collect())
    }
    fn identity(pid: u32) -> ProcessIdentity {
        let mut result = ProcessIdentity {
            pid,
            created_filetime: None,
            executable: None,
        };
        let handle = unsafe { OpenProcess(0x1000, 0, pid) };
        if handle.is_null() {
            return result;
        }
        let mut created = FileTime::default();
        let mut exit = created;
        let mut kernel = created;
        let mut user = created;
        if unsafe { GetProcessTimes(handle, &mut created, &mut exit, &mut kernel, &mut user) } != 0
        {
            result.created_filetime =
                Some((u64::from(created.high) << 32) | u64::from(created.low));
        }
        let mut name = vec![0u16; 32768];
        let mut size = name.len() as u32;
        if unsafe { QueryFullProcessImageNameW(handle, 0, name.as_mut_ptr(), &mut size) } != 0
            && size as usize <= name.len()
        {
            result.executable = Some(String::from_utf16_lossy(&name[..size as usize]));
        }
        unsafe {
            CloseHandle(handle);
        }
        result
    }
    fn v4(address: u32, port: u32) -> SocketAddr {
        SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(address.to_ne_bytes())),
            u16::from_be(port as u16),
        )
    }
    fn v6(address: [u8; 16], port: u32, scope: u32) -> SocketAddr {
        std::net::SocketAddrV6::new(
            Ipv6Addr::from(address),
            u16::from_be(port as u16),
            0,
            u32::from_be(scope),
        )
        .into()
    }
    pub(super) fn snapshot() -> Result<ProcessSnapshot, String> {
        let sampled_at_ms = now_ms();
        let mut endpoints = Vec::new();
        let mut warnings = Vec::new();
        for (tcp, family) in [(true, 2), (true, 23), (false, 2), (false, 23)] {
            let result = table(tcp, family).and_then(|bytes| {
                let mut add = |transport, local, remote, pid| {
                    endpoints.push(EndpointOwner {
                        transport,
                        local,
                        remote,
                        process: ProcessIdentity {
                            pid,
                            created_filetime: None,
                            executable: None,
                        },
                    })
                };
                match (tcp, family) {
                    (true, 2) => {
                        for row in rows::<Tcp4>(&bytes)? {
                            // Closed, listening, TIME_WAIT and deleted rows
                            // cannot identify the sender of a current packet.
                            if (3..=10).contains(&row.state) {
                                add(
                                    Transport::Tcp,
                                    v4(row.local, row.local_port),
                                    Some(v4(row.remote, row.remote_port)),
                                    row.pid,
                                );
                            }
                        }
                    }
                    (true, 23) => {
                        for row in rows::<Tcp6>(&bytes)? {
                            if (3..=10).contains(&row.state) {
                                add(
                                    Transport::Tcp,
                                    v6(row.local, row.local_port, row.local_scope),
                                    Some(v6(row.remote, row.remote_port, row.remote_scope)),
                                    row.pid,
                                );
                            }
                        }
                    }
                    (false, 2) => {
                        for row in rows::<Udp4>(&bytes)? {
                            add(Transport::Udp, v4(row.local, row.local_port), None, row.pid);
                        }
                    }
                    _ => {
                        for row in rows::<Udp6>(&bytes)? {
                            add(
                                Transport::Udp,
                                v6(row.local, row.local_port, row.local_scope),
                                None,
                                row.pid,
                            );
                        }
                    }
                }
                Ok(())
            });
            if let Err(error) = result {
                warnings.push(error);
            }
        }
        if warnings.len() == 4 {
            return Err(warnings.join("; "));
        }
        let mut identities = BTreeMap::new();
        for entry in &mut endpoints {
            entry.process = identities
                .entry(entry.process.pid)
                .or_insert_with(|| identity(entry.process.pid))
                .clone();
        }
        let sampled_filetime = sampled_at_ms
            .saturating_mul(10_000)
            .saturating_add(116_444_736_000_000_000);
        // A process created after table sampling may have reused a PID from a
        // process that exited between the owner-table query and identity lookup.
        endpoints.retain(|entry| {
            entry
                .process
                .created_filetime
                .is_none_or(|created| created <= sampled_filetime)
        });
        Ok(ProcessSnapshot {
            sampled_at_ms,
            completed_at_ms: now_ms(),
            endpoints,
            warnings,
        })
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn documented_row_layouts() {
            assert_eq!(std::mem::size_of::<Tcp4>(), 24);
            assert_eq!(std::mem::size_of::<Tcp6>(), 56);
            assert_eq!(std::mem::size_of::<Udp4>(), 12);
            assert_eq!(std::mem::size_of::<Udp6>(), 28);
        }
    }
}
