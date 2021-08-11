use mobc_redis::redis::RedisError;
use std::io;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    IO(#[from] io::Error),

    #[error("Certificate error: {0}")]
    PKCS8(#[from] pkcs8::Error),

    #[error("JWT error: {0}")]
    JWT(#[from] jsonwebtoken::errors::Error),

    #[error("Redis pool error: {0}")]
    Mobc(#[from] mobc::Error<RedisError>),

    #[error("Redis error: {0}")]
    Redis(#[from] RedisError),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
