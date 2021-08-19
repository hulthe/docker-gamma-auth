use crate::State;
use mobc_redis::redis::{self, aio::ConnectionLike, AsyncCommands, FromRedisValue, RedisError};
use mobc_redis::RedisConnectionManager;

pub type Pool = mobc::Pool<RedisConnectionManager>;
pub type Error = mobc::Error<RedisError>;

pub async fn get(state: &State, key: &str) -> Result<Option<String>, Error> {
    let mut redis_conn = state.redis_pool.get().await?;
    let expires = state.opt.refresh_token_expires as usize;

    // redis_conn.get_ex(...) doesn't exist :(
    Ok(Option::from_redis_value(
        &redis_conn
            .req_packed_command(&redis::cmd("GETEX").arg(key).arg("EX").arg(expires))
            .await?,
    )?)
}

pub async fn set(state: &State, key: &str, value: &str) -> Result<(), Error> {
    let mut redis_conn = state.redis_pool.get().await?;
    let expires = state.opt.refresh_token_expires as usize;

    redis_conn
        .set_ex::<&str, &str, String>(key, value, expires)
        .await?;
    Ok(())
}
