use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use bytes::{BytesMut, Buf};
use serde::{Serialize, Deserialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SocketError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("Frame too large: {0}")]
    FrameTooLarge(usize),
    #[error("Connection closed by peer")]
    ConnectionClosed,
}

/// A SovereignFrame consists of a 4-byte length prefix followed by the JSON payload.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SovereignFrame {
    pub payload: Vec<u8>,
}

pub struct SovereignSocket {
    stream: TcpStream,
    buffer: BytesMut,
}

impl SovereignSocket {
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            buffer: BytesMut::with_capacity(4096),
        }
    }

    /// Sends a frame over the wire.
    pub async fn send_frame(&mut self, data: &[u8]) -> Result<(), SocketError> {
        let len = data.len() as u32;
        let len_bytes = len.to_be_bytes();

        // Write length prefix and then the payload
        self.stream.write_all(&len_bytes).await?;
        self.stream.write_all(data).await?;
        self.stream.flush().await?;

        Ok(())
    }

    /// Reads a frame from the wire, accumulating in the buffer to solve TCP fragmentation.
    pub async fn receive_frame(&mut self) -> Result<Vec<u8>, SocketError> {
        loop {
            // Try to read a frame from the existing buffer
            if self.buffer.len() >= 4 {
                let mut len_bytes = [0u8; 4];
                len_bytes.copy_from_slice(&self.buffer[..4]);
                let len = u32::from_be_bytes(len_bytes) as usize;

                if len > 10 * 1024 * 1024 { // 10MB Limit
                    return Err(SocketError::FrameTooLarge(len));
                }

                if self.buffer.len() >= 4 + len {
                    // We have a full frame
                    self.buffer.advance(4);
                    let payload = self.buffer.split_to(len).to_vec();
                    return Ok(payload);
                }
            }

            // Not enough data in buffer, read more from the stream
            let mut temp_buf = [0u8; 4096];
            let n = self.stream.read(&mut temp_buf).await?;
            if n == 0 {
                return Err(SocketError::ConnectionClosed);
            }
            self.buffer.extend_from_slice(&temp_buf[..n]);
        }
    }
}
