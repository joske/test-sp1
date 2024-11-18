use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Input {
    pub a: u64,
    pub b: u64,
    pub verification_key: [u32; 8],
}
