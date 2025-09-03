use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("given challenge name not found: {name}")]
    InvalidChallengeName { name: String },

    #[error("given validation mode not found: {mode}")]
    InvalidValidationMode { mode: String },

    #[error("failed to parse embedded checks YAML: {source}")]
    PatternLoad {
        #[from]
        source: serde_yaml::Error,
    },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
