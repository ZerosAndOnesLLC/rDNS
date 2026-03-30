use crate::protocol::message::Message;
use crate::protocol::name::DnsName;
use crate::protocol::record::RecordType;
use std::net::SocketAddr;
use std::time::Duration;

/// Forward a DNS query to configured upstream resolvers.
/// Tries each forwarder in order until one responds.
pub async fn forward(
    question_name: &DnsName,
    question_type: RecordType,
    forwarders: &[SocketAddr],
    timeout: Duration,
) -> anyhow::Result<Message> {
    let mut last_error = None;

    for server in forwarders {
        match forward_to_server(question_name, question_type, *server, timeout).await {
            Ok(resp) => return Ok(resp),
            Err(e) => {
                tracing::debug!(%server, error = %e, "Forwarder query failed");
                last_error = Some(e);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("No forwarders configured")))
}

/// Forward query to a single upstream server with RD (Recursion Desired) set.
async fn forward_to_server(
    question_name: &DnsName,
    question_type: RecordType,
    server: SocketAddr,
    timeout: Duration,
) -> anyhow::Result<Message> {
    use crate::protocol::header::Header;
    use crate::protocol::opcode::Opcode;
    use crate::protocol::rcode::Rcode;
    use crate::protocol::record::{Question, RecordClass};
    use tokio::net::UdpSocket;

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
            rd: true, // Set RD for forwarding — upstream does the recursion
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
