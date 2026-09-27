use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const DEFAULT_SOCKET: &str = "/run/agent-keyring/control.sock";

#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Get { key: String, non_interactive: bool },
    Create { key: String, value: Vec<u8> },
    Replace { key: String, value: Vec<u8> },
    Delete { key: String },
    Grants,
    Revoke { all: bool, key: Option<String> },
    Ping,
}

impl Drop for Request {
    fn drop(&mut self) {
        match self {
            Self::Create { value, .. } | Self::Replace { value, .. } => value.zeroize(),
            _ => {}
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Agent {
    pub name: String,
    pub pid: i32,
    pub start_time: u64,
    pub executable: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GrantInfo {
    pub key: String,
    pub version: u64,
    pub agent: Agent,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum Response {
    Value { value: Vec<u8> },
    Written { version: u64 },
    Grants { grants: Vec<GrantInfo> },
    Revoked { count: usize },
    Pong { version: String },
    Error { code: ErrorCode, message: String },
}

impl Drop for Response {
    fn drop(&mut self) {
        if let Self::Value { value } = self {
            value.zeroize();
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidRequest,
    NotFound,
    Denied,
    Unavailable,
    AlreadyExists,
    Conflict,
    NotAgent,
    Internal,
}

impl ErrorCode {
    pub fn exit_status(self) -> u8 {
        match self {
            Self::Internal => 1,
            Self::InvalidRequest => 2,
            Self::NotFound => 3,
            Self::Denied => 4,
            Self::Unavailable => 5,
            Self::AlreadyExists => 6,
            Self::Conflict => 7,
            Self::NotAgent => 8,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_values_round_trip_without_trimming() {
        let request = Request::Create {
            key: "app.token".into(),
            value: vec![0, 255, b'\n'],
        };
        let encoded = serde_json::to_vec(&request).unwrap();
        let parsed: Request = serde_json::from_slice(&encoded).unwrap();
        assert!(matches!(&parsed, Request::Create { value, .. } if value == &[0, 255, b'\n']));
    }

    #[test]
    fn client_identity_and_approval_fields_are_not_accepted() {
        for json in [
            r#"{"operation":"get","key":"app.token","non_interactive":false,"pid":1}"#,
            r#"{"operation":"get","key":"app.token","non_interactive":false,"approved":true}"#,
            r#"{"operation":"approve","key":"app.token"}"#,
        ] {
            assert!(serde_json::from_str::<Request>(json).is_err());
        }
    }
}
