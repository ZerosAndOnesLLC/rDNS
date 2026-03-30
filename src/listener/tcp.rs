use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Serve DNS queries over TCP on the given address.
/// TCP DNS uses a 2-byte length prefix before each message (RFC 1035 Section 4.2.2).
pub async fn serve(addr: SocketAddr) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "TCP listener bound");

    loop {
        let (stream, src) = listener.accept().await?;
        tokio::spawn(handle_connection(stream, src));
    }
}

async fn handle_connection(mut stream: tokio::net::TcpStream, src: SocketAddr) {
    if let Err(e) = handle_connection_inner(&mut stream, src).await {
        tracing::debug!(%src, error = %e, "TCP connection error");
    }
}

async fn handle_connection_inner(
    stream: &mut tokio::net::TcpStream,
    src: SocketAddr,
) -> anyhow::Result<()> {
    // TCP DNS connections can send multiple queries on the same connection.
    // Each message is prefixed with a 2-byte big-endian length.
    loop {
        // Read 2-byte length prefix
        let len = match stream.read_u16().await {
            Ok(len) => len as usize,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // Client closed connection
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        };

        if len == 0 || len > 65535 {
            return Ok(());
        }

        // Read the DNS message
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;

        tracing::debug!(%src, bytes = len, "TCP query received");

        let response = super::handle_query(&buf);

        // Write 2-byte length prefix + response
        let resp_len = response.len() as u16;
        stream.write_u16(resp_len).await?;
        stream.write_all(&response).await?;
        stream.flush().await?;
    }
}
