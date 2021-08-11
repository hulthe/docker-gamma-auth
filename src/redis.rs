use crate::{error::Error, RedisPool};
use mobc_redis::redis::AsyncCommands;

pub async fn get(redis_pool: &RedisPool, key: &str) -> Result<String, Error> {
    let mut redis_conn = redis_pool.get().await?;
    Ok(redis_conn.get(key).await?)
}

pub async fn set(redis_pool: &RedisPool, key: &str, value: &str) -> Result<(), Error> {
    let mut redis_conn = redis_pool.get().await?;
    redis_conn.set::<&str, &str, String>(key, value).await?;
    Ok(())
}
