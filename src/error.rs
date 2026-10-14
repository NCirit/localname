use serde::{Deserialize, Serialize};

/// Stable error categories exposed in JSON output and process exit codes.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    InvalidInput,
    PermissionRequired,
    Conflict,
    Unavailable,
    VerificationFailed,
    #[serde(rename = "INTERNAL_ERROR")]
    Internal,
}

impl ErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput => "INVALID_INPUT",
            Self::PermissionRequired => "PERMISSION_REQUIRED",
            Self::Conflict => "CONFLICT",
            Self::Unavailable => "UNAVAILABLE",
            Self::VerificationFailed => "VERIFICATION_FAILED",
            Self::Internal => "INTERNAL_ERROR",
        }
    }

    pub const fn exit_code(self) -> u8 {
        match self {
            Self::InvalidInput => 3,
            Self::PermissionRequired => 4,
            Self::Conflict => 5,
            Self::Unavailable => 6,
            Self::VerificationFailed => 7,
            Self::Internal => 70,
        }
    }
}

/// An error carrying an explicit category; it takes precedence over message heuristics.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct CodedError {
    pub code: ErrorCode,
    pub message: String,
}

pub fn coded(code: ErrorCode, message: impl Into<String>) -> anyhow::Error {
    CodedError {
        code,
        message: message.into(),
    }
    .into()
}

/// Classify an error chain. Explicit codes win; I/O kinds are next; message text is a fallback.
pub fn classify(error: &anyhow::Error) -> ErrorCode {
    for cause in error.chain() {
        if let Some(coded) = cause.downcast_ref::<CodedError>() {
            return coded.code;
        }
    }
    for cause in error.chain() {
        if let Some(error) = cause.downcast_ref::<std::io::Error>() {
            match error.kind() {
                std::io::ErrorKind::NotFound
                | std::io::ErrorKind::ConnectionRefused
                | std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::NotConnected => return ErrorCode::Unavailable,
                std::io::ErrorKind::PermissionDenied => return ErrorCode::PermissionRequired,
                std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::AddrInUse => {
                    return ErrorCode::Conflict;
                }
                _ => {}
            }
        }
    }
    let message = format!("{error:#}").to_ascii_lowercase();
    if message.contains("permission") || message.contains("access denied") {
        ErrorCode::PermissionRequired
    } else if message.contains("stale")
        || message.contains("conflict")
        || message.contains("already exists")
    {
        ErrorCode::Conflict
    } else if message.contains("timed out")
        || message.contains("unavailable")
        || message.contains("not found")
    {
        ErrorCode::Unavailable
    } else if message.contains("invalid")
        || message.contains("unsupported")
        || message.contains("required")
    {
        ErrorCode::InvalidInput
    } else {
        ErrorCode::Internal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_code_wins_over_message_text() {
        let error = coded(ErrorCode::Conflict, "invalid looking text").context("outer");
        assert_eq!(classify(&error), ErrorCode::Conflict);
    }

    #[test]
    fn serialized_names_match_schema() {
        assert_eq!(
            serde_json::to_string(&ErrorCode::Internal).unwrap(),
            "\"INTERNAL_ERROR\""
        );
        assert_eq!(
            serde_json::to_string(&ErrorCode::VerificationFailed).unwrap(),
            "\"VERIFICATION_FAILED\""
        );
    }
}
