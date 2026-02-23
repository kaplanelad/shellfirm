//! Typed error types for shellfirm.

use std::time::SystemTimeError;

/// All errors produced by the shellfirm library.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Yaml(#[from] serde_yaml::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[cfg(feature = "llm")]
    #[error(transparent)]
    Http(#[from] reqwest::Error),

    #[error(transparent)]
    SystemTime(#[from] SystemTimeError),

    #[error("{0}")]
    Config(String),

    #[cfg(feature = "mcp")]
    #[error("{0}")]
    Mcp(String),

    #[error("{0}")]
    Prompt(String),

    #[cfg(feature = "wrap")]
    #[error("{0}")]
    Wrap(String),

    #[cfg(feature = "llm")]
    #[error("{0}")]
    LlmApi(String),

    #[error("{0}")]
    Other(String),
}

/// A `Result` alias where the error type is [`Error`].
pub type Result<T> = std::result::Result<T, Error>;
