use crate::protocol::message::Message;
use crate::protocol::name::DnsName;
use crate::protocol::record::RecordType;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, oneshot};

/// A pool of UDP sockets for forwarding queries to upstream resolvers.
/// Reuses sockets and multiplexes queries by ID.
#[derive(Clone)]
pub struct ForwarderPool {
    inner: Arc<ForwarderPoolInner>,
}

struct ForwarderPoolInner {
    socket: UdpSocket,
    /// Pending queries waiting for responses, keyed by query ID
    pending: Mutex<HashMap<u16, oneshot::Sender<Message>>>,
}

impl ForwarderPool {
    /// Create a new forwarder pool connected to the given server.
    pub async fn new(server: SocketAddr) -> anyhow::Result<Self> {
        let bind_addr = if server.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind_addr).await?;
        socket.connect(server).await?;

        let pool = Self {
            inner: Arc::new(ForwarderPoolInner {
                socket,
                pending: Mutex::new(HashMap::new()),
            }),
        };

        // Spawn the response receiver loop
        let pool_clone = pool.clone();
        tokio::spawn(async move {
            pool_clone.recv_loop().await;
        });

        Ok(pool)
    }

    /// Send a query and wait for the response.
    pub async fn query(
        &self,
        name: &DnsName,
        rtype: RecordType,
        timeout: Duration,
    ) -> anyhow::Result<Message> {
        use crate::protocol::header::Header;
        use crate::protocol::opcode::Opcode;
        use crate::protocol::rcode::Rcode;
        use crate::protocol::record::{Question, RecordClass};

        // Generate a unique query ID, avoiding collisions with in-flight queries
        let id = {
            let pending = self.inner.pending.lock().await;
            let mut id = super::iterator::rand_id();
            let mut attempts = 0;
            while pending.contains_key(&id) && attempts < 16 {
                id = super::iterator::rand_id();
                attempts += 1;
            }
            id
        };

        let msg = Message {
            header: Header {
                id,
                qr: false,
                opcode: Opcode::Query,
                aa: false,
                tc: false,
                rd: true,
                ra: false,
                ad: false,
                cd: false,
                rcode: Rcode::NoError,
                qd_count: 1,
                an_count: 0,
                ns_count: 0,
                ar_count: 0,
            },
            questions: vec![Question {
                name: name.clone(),
                qtype: rtype,
                qclass: RecordClass::IN,
            }],
            answers: vec![],
            authority: vec![],
            additional: vec![],
        };

        let wire = msg.encode();

        // Register the pending query
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.inner.pending.lock().await;
            pending.insert(id, tx);
        }

        // Send the query
        if let Err(e) = self.inner.socket.send(&wire).await {
            let mut pending = self.inner.pending.lock().await;
            pending.remove(&id);
            return Err(e.into());
        }

        // Wait for the response with timeout
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => {
                anyhow::bail!("Forwarder response channel closed")
            }
            Err(_) => {
                let mut pending = self.inner.pending.lock().await;
                pending.remove(&id);
                anyhow::bail!("Forwarder query timed out")
            }
        }
    }

    /// Background loop that receives responses and dispatches to waiting queries.
    async fn recv_loop(&self) {
        let mut buf = vec![0u8; 4096];
        loop {
            let len = match self.inner.socket.recv(&mut buf).await {
                Ok(len) => len,
                Err(e) => {
                    tracing::debug!(error = %e, "Forwarder recv error");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
            };

            // Parse just the ID from the first 2 bytes (fast path)
            if len < 2 {
                continue;
            }
            let id = u16::from_be_bytes([buf[0], buf[1]]);

            // Look up the pending query
            let sender = {
                let mut pending = self.inner.pending.lock().await;
                pending.remove(&id)
            };

            if let Some(tx) = sender {
                match Message::decode(&buf[..len]) {
                    Ok(response) => {
                        let _ = tx.send(response);
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "Failed to decode forwarder response");
                    }
                }
            }
            // If no pending query for this ID, it's a late/duplicate response — drop it
        }
    }
}

/// Forward a DNS query using forwarder pools.
/// Falls back to single-shot if pools aren't available.
pub async fn forward(
    question_name: &DnsName,
    question_type: RecordType,
    forwarders: &[SocketAddr],
    timeout: Duration,
) -> anyhow::Result<Message> {
    let mut last_error = None;

    for server in forwarders {
        match forward_single(question_name, question_type, *server, timeout).await {
            Ok(resp) => return Ok(resp),
            Err(e) => {
                tracing::debug!(%server, error = %e, "Forwarder query failed");
                last_error = Some(e);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("No forwarders configured")))
}

/// Single-shot forward for when we don't have a pool.
async fn forward_single(
    question_name: &DnsName,
    question_type: RecordType,
    server: SocketAddr,
    timeout: Duration,
) -> anyhow::Result<Message> {
    use crate::protocol::header::Header;
    use crate::protocol::opcode::Opcode;
    use crate::protocol::rcode::Rcode;
    use crate::protocol::record::{Question, RecordClass};

    let socket = UdpSocket::bind(if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await?;

    let id = super::iterator::rand_id();

    let query = Message {
        header: Header {
            id,
            qr: false,
            opcode: Opcode::Query,
            aa: false,
            tc: false,
            rd: true,
            ra: false,
            ad: false,
            cd: false,
            rcode: Rcode::NoError,
            qd_count: 1,
            an_count: 0,
            ns_count: 0,
            ar_count: 0,
        },
        questions: vec![Question {
            name: question_name.clone(),
            qtype: question_type,
            qclass: RecordClass::IN,
        }],
        answers: vec![],
        authority: vec![],
        additional: vec![],
    };

    let wire = query.encode();
    socket.send_to(&wire, server).await?;

    let mut buf = vec![0u8; 4096];
    let len = tokio::time::timeout(timeout, async {
        loop {
            let (len, src) = socket.recv_from(&mut buf).await?;
            if src.ip() == server.ip() {
                return Ok::<usize, std::io::Error>(len);
            }
        }
    })
    .await??;

    let response = Message::decode(&buf[..len])?;
    if response.header.id != id {
        anyhow::bail!("Forwarder response ID mismatch");
    }

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_forward_no_forwarders() {
        let name = DnsName::from_str("example.com").unwrap();
        let result = forward(&name, RecordType::A, &[], Duration::from_secs(2)).await;
        assert!(result.is_err());
    }
}
