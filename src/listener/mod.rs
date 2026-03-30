pub mod tcp;
pub mod udp;

use crate::protocol::Message;

/// Process an incoming DNS query and produce a response.
/// For now, returns SERVFAIL for all queries. This will be replaced
/// with actual resolver/auth engine routing.
fn handle_query(buf: &[u8]) -> Vec<u8> {
    match Message::decode(buf) {
        Ok(query) => {
            tracing::debug!(
                id = query.header.id,
                questions = query.header.qd_count,
                "Received query"
            );
            let response = Message::servfail(&query);
            response.encode()
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to parse query");
            // Try to extract the ID from the first 2 bytes for the error response
            let id = if buf.len() >= 2 {
                u16::from_be_bytes([buf[0], buf[1]])
            } else {
                0
            };
            Message::formerr(id).encode()
        }
    }
}
