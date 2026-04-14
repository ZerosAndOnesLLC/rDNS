//! High-performance UDP I/O using recvmmsg/sendmmsg on Linux via the
//! safe `nix` wrappers. Falls back to standard recv_from/send_to on
//! other platforms.
//!
//! This module is `#![forbid(unsafe_code)]` — every syscall goes
//! through an audited `nix` wrapper.

#![forbid(unsafe_code)]

use std::io;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

/// Maximum packets to receive/send in a single syscall
const BATCH_SIZE: usize = 64;
/// Maximum DNS UDP packet size
const PKT_SIZE: usize = 4096;

/// A received UDP packet with its source address and length.
pub struct RecvPacket {
    pub buf: [u8; PKT_SIZE],
    pub len: usize,
    pub src: SocketAddr,
}

/// A response to send.
pub struct SendPacket {
    pub data: Vec<u8>,
    pub dest: SocketAddr,
}

/// Batch-receive UDP packets using recvmmsg (Linux only).
/// Returns the number of packets received.
#[cfg(target_os = "linux")]
pub fn recvmmsg_batch(fd: i32, packets: &mut [RecvPacket]) -> io::Result<usize> {
    use nix::sys::socket::{MsgFlags, MultiHeaders, SockaddrStorage, recvmmsg};
    use std::io::IoSliceMut;

    let batch = packets.len().min(BATCH_SIZE);
    if batch == 0 {
        return Ok(0);
    }

    let mut headers: MultiHeaders<SockaddrStorage> = MultiHeaders::preallocate(batch, None);

    // Collect (bytes_received, source_address) pairs inside this scope so
    // the iovec borrows from `packets` are released before we mutate
    // `packets[i].len` / `.src` below.
    let collected: Vec<(usize, Option<SockaddrStorage>)> = {
        let mut slice_groups: Vec<[IoSliceMut<'_>; 1]> = packets[..batch]
            .iter_mut()
            .map(|p| [IoSliceMut::new(&mut p.buf[..])])
            .collect();

        recvmmsg(
            fd,
            &mut headers,
            slice_groups.iter_mut(),
            MsgFlags::MSG_WAITFORONE,
            None,
        )
        .map_err(io::Error::from)?
        .map(|r| (r.bytes, r.address))
        .collect()
    };

    let count = collected.len();
    for (i, (bytes, addr)) in collected.into_iter().enumerate() {
        packets[i].len = bytes;
        if let Some(addr) = addr {
            packets[i].src = sockaddr_storage_to_socketaddr(&addr);
        }
    }

    Ok(count)
}

/// Batch-send UDP packets using sendmmsg (Linux only).
#[cfg(target_os = "linux")]
pub fn sendmmsg_batch(fd: i32, packets: &[SendPacket]) -> io::Result<usize> {
    use nix::sys::socket::{MsgFlags, MultiHeaders, SockaddrStorage, sendmmsg};
    use std::io::IoSlice;

    let batch = packets.len().min(BATCH_SIZE);
    if batch == 0 {
        return Ok(0);
    }

    let mut headers: MultiHeaders<SockaddrStorage> = MultiHeaders::preallocate(batch, None);

    let slice_groups: Vec<[IoSlice<'_>; 1]> = packets[..batch]
        .iter()
        .map(|p| [IoSlice::new(&p.data)])
        .collect();

    let addrs: Vec<Option<SockaddrStorage>> = packets[..batch]
        .iter()
        .map(|p| Some(SockaddrStorage::from(p.dest)))
        .collect();

    let results = sendmmsg(
        fd,
        &mut headers,
        slice_groups.iter(),
        &addrs,
        [],
        MsgFlags::empty(),
    )
    .map_err(io::Error::from)?;

    Ok(results.count())
}

#[cfg(target_os = "linux")]
fn sockaddr_storage_to_socketaddr(ss: &nix::sys::socket::SockaddrStorage) -> SocketAddr {
    if let Some(sa4) = ss.as_sockaddr_in() {
        SocketAddr::V4(SocketAddrV4::new(sa4.ip(), sa4.port()))
    } else if let Some(sa6) = ss.as_sockaddr_in6() {
        SocketAddr::V6(SocketAddrV6::new(
            sa6.ip(),
            sa6.port(),
            sa6.flowinfo(),
            sa6.scope_id(),
        ))
    } else {
        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
    }
}

// Non-Linux stubs
#[cfg(not(target_os = "linux"))]
pub fn recvmmsg_batch(_fd: i32, _packets: &mut [RecvPacket]) -> io::Result<usize> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "recvmmsg not available",
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn sendmmsg_batch(_fd: i32, _packets: &[SendPacket]) -> io::Result<usize> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "sendmmsg not available",
    ))
}

/// Create pre-allocated receive packet batch.
pub fn alloc_recv_batch(count: usize) -> Vec<RecvPacket> {
    (0..count)
        .map(|_| RecvPacket {
            buf: [0u8; PKT_SIZE],
            len: 0,
            src: SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0),
        })
        .collect()
}
