use crate::login::User;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SessionData {
    pub id: String,
    pub user: Option<User>,
    pub ts: u128,
}

impl Default for SessionData {
    fn default() -> Self {
        SessionData {
            id: Self::gen_id(),
            user: Default::default(),
            ts: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        }
    }
}

impl SessionData {
    pub fn gen_id() -> String {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        base64::encode(&key)
    }

    pub fn logged_in(&self) -> bool {
        self.user.is_some()
    }
}
