//! High-performance UDP I/O using recvmmsg/sendmmsg on Linux.
//! Falls back to standard recv_from/send_to on other platforms.

use std::io;
use std::net::SocketAddr;

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
pub fn recvmmsg_batch(
    fd: i32,
    packets: &mut [RecvPacket],
) -> io::Result<usize> {
    use std::mem::zeroed;

    let batch = packets.len().min(BATCH_SIZE);
    if batch == 0 {
        return Ok(0);
    }

    let mut iovecs: Vec<libc::iovec> = Vec::with_capacity(batch);
    let mut msgs: Vec<libc::mmsghdr> = Vec::with_capacity(batch);
    let mut addrs: Vec<libc::sockaddr_storage> = Vec::with_capacity(batch);

    for i in 0..batch {
        addrs.push(unsafe { zeroed() });
        iovecs.push(libc::iovec {
            iov_base: packets[i].buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: PKT_SIZE,
        });
    }

    for i in 0..batch {
        let mut hdr: libc::mmsghdr = unsafe { zeroed() };
        hdr.msg_hdr.msg_name = &mut addrs[i] as *mut _ as *mut libc::c_void;
        hdr.msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as u32;
        hdr.msg_hdr.msg_iov = &mut iovecs[i];
        hdr.msg_hdr.msg_iovlen = 1;
        msgs.push(hdr);
    }

    let ret = unsafe {
        libc::recvmmsg(
            fd,
            msgs.as_mut_ptr(),
            batch as u32,
            libc::MSG_WAITFORONE,
            std::ptr::null_mut(),
        )
    };

    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    let count = ret as usize;

    // Extract results
    for i in 0..count {
        packets[i].len = msgs[i].msg_len as usize;
        packets[i].src = sockaddr_to_socketaddr(&addrs[i], msgs[i].msg_hdr.msg_namelen);
    }

    Ok(count)
}

/// Batch-send UDP packets using sendmmsg (Linux only).
#[cfg(target_os = "linux")]
pub fn sendmmsg_batch(
    fd: i32,
    packets: &[SendPacket],
) -> io::Result<usize> {
    use std::mem::zeroed;

    let batch = packets.len().min(BATCH_SIZE);
    if batch == 0 {
        return Ok(0);
    }

    let mut addrs: Vec<libc::sockaddr_storage> = Vec::with_capacity(batch);
    let mut addr_lens: Vec<u32> = Vec::with_capacity(batch);
    let mut iovecs: Vec<libc::iovec> = Vec::with_capacity(batch);
    let mut msgs: Vec<libc::mmsghdr> = Vec::with_capacity(batch);

    for pkt in packets.iter().take(batch) {
        let (addr, len) = socketaddr_to_sockaddr(&pkt.dest);
        addrs.push(addr);
        addr_lens.push(len);
        iovecs.push(libc::iovec {
            iov_base: pkt.data.as_ptr() as *mut libc::c_void,
            iov_len: pkt.data.len(),
        });
    }

    for i in 0..batch {
        let mut hdr: libc::mmsghdr = unsafe { zeroed() };
        hdr.msg_hdr.msg_name = &mut addrs[i] as *mut _ as *mut libc::c_void;
        hdr.msg_hdr.msg_namelen = addr_lens[i];
        hdr.msg_hdr.msg_iov = &mut iovecs[i];
        hdr.msg_hdr.msg_iovlen = 1;
        msgs.push(hdr);
    }

    let ret = unsafe {
        libc::sendmmsg(fd, msgs.as_mut_ptr(), batch as u32, 0)
    };

    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(ret as usize)
}

#[cfg(target_os = "linux")]
fn sockaddr_to_socketaddr(addr: &libc::sockaddr_storage, _len: u32) -> SocketAddr {
    unsafe {
        if addr.ss_family == libc::AF_INET as u16 {
            let addr4 = &*(addr as *const _ as *const libc::sockaddr_in);
            SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(addr4.sin_addr.s_addr))),
                u16::from_be(addr4.sin_port),
            )
        } else {
            let addr6 = &*(addr as *const _ as *const libc::sockaddr_in6);
            SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(addr6.sin6_addr.s6_addr)),
                u16::from_be(addr6.sin6_port),
            )
        }
    }
}

#[cfg(target_os = "linux")]
fn socketaddr_to_sockaddr(addr: &SocketAddr) -> (libc::sockaddr_storage, u32) {
    unsafe {
        let mut storage: libc::sockaddr_storage = std::mem::zeroed();
        match addr {
            SocketAddr::V4(a) => {
                let s = &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in);
                s.sin_family = libc::AF_INET as _;
                s.sin_port = a.port().to_be();
                s.sin_addr.s_addr = u32::from(*a.ip()).to_be();
                (storage, std::mem::size_of::<libc::sockaddr_in>() as u32)
            }
            SocketAddr::V6(a) => {
                let s = &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in6);
                s.sin6_family = libc::AF_INET6 as _;
                s.sin6_port = a.port().to_be();
                s.sin6_addr.s6_addr = a.ip().octets();
                (storage, std::mem::size_of::<libc::sockaddr_in6>() as u32)
            }
        }
    }
}

// Non-Linux stubs
#[cfg(not(target_os = "linux"))]
pub fn recvmmsg_batch(_fd: i32, _packets: &mut [RecvPacket]) -> io::Result<usize> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "recvmmsg not available"))
}

#[cfg(not(target_os = "linux"))]
pub fn sendmmsg_batch(_fd: i32, _packets: &[SendPacket]) -> io::Result<usize> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "sendmmsg not available"))
}

/// Convert a SocketAddr to raw libc sockaddr_storage (public for SO_REUSEPORT binding).
pub fn socketaddr_to_sockaddr_raw(addr: &SocketAddr) -> (libc::sockaddr_storage, u32) {
    unsafe {
        let mut storage: libc::sockaddr_storage = std::mem::zeroed();
        match addr {
            SocketAddr::V4(a) => {
                let s = &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in);
                s.sin_family = libc::AF_INET as _;
                s.sin_port = a.port().to_be();
                s.sin_addr.s_addr = u32::from(*a.ip()).to_be();
                (storage, std::mem::size_of::<libc::sockaddr_in>() as u32)
            }
            SocketAddr::V6(a) => {
                let s = &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in6);
                s.sin6_family = libc::AF_INET6 as _;
                s.sin6_port = a.port().to_be();
                s.sin6_addr.s6_addr = a.ip().octets();
                (storage, std::mem::size_of::<libc::sockaddr_in6>() as u32)
            }
        }
    }
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
