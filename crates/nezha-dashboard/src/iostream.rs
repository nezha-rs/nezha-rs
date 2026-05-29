use std::{collections::HashMap, sync::Arc};

use tokio::sync::{Mutex, Notify, RwLock, mpsc};

const STREAM_MAGIC: [u8; 4] = [0xff, 0x05, 0xff, 0x05];
const STREAM_BUFFER: usize = 64;

#[derive(Debug, Default)]
pub(crate) struct IoStreamRegistry {
    streams: RwLock<HashMap<String, Arc<IoStreamSession>>>,
}

#[derive(Debug)]
pub(crate) struct IoStreamSession {
    creator_user_id: u64,
    target_server_id: u64,
    agent_connected: Notify,
    to_agent_tx: mpsc::Sender<Vec<u8>>,
    to_agent_rx: Mutex<Option<mpsc::Receiver<Vec<u8>>>>,
    to_user_tx: mpsc::Sender<Vec<u8>>,
    to_user_rx: Mutex<Option<mpsc::Receiver<Vec<u8>>>>,
}

impl IoStreamRegistry {
    pub(crate) async fn create_stream(
        &self,
        stream_id: String,
        creator_user_id: u64,
        target_server_id: u64,
    ) {
        let (to_agent_tx, to_agent_rx) = mpsc::channel(STREAM_BUFFER);
        let (to_user_tx, to_user_rx) = mpsc::channel(STREAM_BUFFER);

        self.streams.write().await.insert(
            stream_id,
            Arc::new(IoStreamSession {
                creator_user_id,
                target_server_id,
                agent_connected: Notify::new(),
                to_agent_tx,
                to_agent_rx: Mutex::new(Some(to_agent_rx)),
                to_user_tx,
                to_user_rx: Mutex::new(Some(to_user_rx)),
            }),
        );
    }

    pub(crate) async fn get_stream(&self, stream_id: &str) -> Option<Arc<IoStreamSession>> {
        self.streams.read().await.get(stream_id).cloned()
    }

    pub(crate) async fn close_stream(&self, stream_id: &str) {
        self.streams.write().await.remove(stream_id);
    }

    pub(crate) async fn is_stream_authorized_for_user(
        &self,
        stream_id: &str,
        user_id: u64,
        is_admin: bool,
    ) -> bool {
        let Some(stream) = self.get_stream(stream_id).await else {
            return false;
        };
        is_admin || stream.creator_user_id == user_id
    }
}

impl IoStreamSession {
    pub(crate) fn is_authorized_for_agent(&self, server_id: u64) -> bool {
        self.target_server_id != 0 && self.target_server_id == server_id
    }

    pub(crate) async fn take_agent_receiver(&self) -> Option<mpsc::Receiver<Vec<u8>>> {
        self.to_agent_rx.lock().await.take()
    }

    pub(crate) fn mark_agent_connected(&self) {
        self.agent_connected.notify_waiters();
    }

    pub(crate) async fn wait_agent_connected(&self, timeout: std::time::Duration) -> bool {
        if self.to_agent_rx.lock().await.is_none() {
            return true;
        }
        tokio::time::timeout(timeout, self.agent_connected.notified())
            .await
            .is_ok()
    }

    pub(crate) async fn take_user_receiver(&self) -> Option<mpsc::Receiver<Vec<u8>>> {
        self.to_user_rx.lock().await.take()
    }

    pub(crate) async fn send_to_agent(
        &self,
        data: Vec<u8>,
    ) -> Result<(), mpsc::error::SendError<Vec<u8>>> {
        self.to_agent_tx.send(data).await
    }

    pub(crate) async fn send_to_user(
        &self,
        data: Vec<u8>,
    ) -> Result<(), mpsc::error::SendError<Vec<u8>>> {
        self.to_user_tx.send(data).await
    }
}

pub(crate) fn is_valid_stream_magic(data: &[u8]) -> bool {
    data.len() >= STREAM_MAGIC.len() && data[..STREAM_MAGIC.len()] == STREAM_MAGIC
}

pub(crate) fn stream_id_from_init(data: &[u8]) -> Option<String> {
    if !is_valid_stream_magic(data) || data.len() == STREAM_MAGIC.len() {
        return None;
    }
    String::from_utf8(data[STREAM_MAGIC.len()..].to_vec()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_exact_iostream_magic() {
        assert!(is_valid_stream_magic(&[0xff, 0x05, 0xff, 0x05]));
        assert!(is_valid_stream_magic(&[
            0xff, 0x05, 0xff, 0x05, b's', b't', b'r', b'e', b'a', b'm'
        ]));
        assert!(!is_valid_stream_magic(&[]));
        assert!(!is_valid_stream_magic(&[0xff, 0x05, 0xff]));
        assert!(!is_valid_stream_magic(&[0xff, 0x00, 0xff, 0x05]));
        assert!(!is_valid_stream_magic(&[0xff, 0x05, 0xff, 0x00]));
    }

    #[tokio::test]
    async fn authorizes_only_creator_or_admin_user() {
        let registry = IoStreamRegistry::default();
        registry.create_stream("stream".into(), 100, 7).await;

        assert!(
            registry
                .is_stream_authorized_for_user("stream", 100, false)
                .await
        );
        assert!(
            registry
                .is_stream_authorized_for_user("stream", 200, true)
                .await
        );
        assert!(
            !registry
                .is_stream_authorized_for_user("stream", 200, false)
                .await
        );
        assert!(
            !registry
                .is_stream_authorized_for_user("missing", 100, true)
                .await
        );
    }

    #[tokio::test]
    async fn authorizes_only_bound_agent_server() {
        let registry = IoStreamRegistry::default();
        registry.create_stream("stream".into(), 100, 7).await;
        let stream = registry.get_stream("stream").await.unwrap();

        assert!(stream.is_authorized_for_agent(7));
        assert!(!stream.is_authorized_for_agent(8));
        assert!(!stream.is_authorized_for_agent(0));
    }
}
