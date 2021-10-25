mod error;
mod gamma;
mod method;
mod opt;
mod redis;
mod response;
mod token;
mod util;

#[macro_use]
extern crate log;

use async_std::fs;
use dotenv::dotenv;
use http_types::headers::HeaderValue;
use jsonwebtoken::EncodingKey;
use mobc::Pool;
use mobc_redis::{redis::Client, RedisConnectionManager};
use pkcs8::{FromPrivateKey, PublicKeyDocument, ToPublicKey};
use rsa::RsaPrivateKey;
use std::sync::Arc;
use tide::security::{CorsMiddleware, Origin};
use tide::utils::After;

use crate::error::Error;
use crate::opt::Opt;

#[derive(Clone)]
pub struct State {
    pub_key: Arc<PublicKeyDocument>,
    jwt_enc_key: Arc<EncodingKey>,
    opt: Arc<Opt>,
    redis_pool: redis::Pool,
}

#[async_std::main]
async fn main() {
    dotenv().ok();
    env_logger::init();

    if let Err(e) = run().await {
        error!("{}", e);
    }
}

async fn run() -> Result<(), Error> {
    let pem = fs::read_to_string("certs/RootCA.key").await?;

    let priv_key = RsaPrivateKey::from_pkcs8_pem(&pem)?;
    let jwt_enc_key = EncodingKey::from_rsa_pem(pem.as_bytes())?;

    let opt = Opt::from_env()?;
    let port = opt.port;

    let client = Client::open(opt.redis_host.clone())?;
    let manager = RedisConnectionManager::new(client);
    let redis_pool = Pool::builder().build(manager);

    let state = State {
        pub_key: Arc::new(priv_key.to_public_key_der()?),
        jwt_enc_key: Arc::new(jwt_enc_key),
        opt: Arc::new(opt),
        redis_pool,
    };

    let mut app = tide::with_state(state);
    app.with(After(error::handler));
    app.with(
        CorsMiddleware::new()
            .allow_methods(
                "GET, POST, OPTIONS"
                    .parse::<HeaderValue>()
                    .expect("infallible"),
            )
            .allow_origin(Origin::from("*"))
            .allow_credentials(false),
    );
    app.at("/token")
        .get(method::issue_token::handler)
        .post(method::refresh_token::handler);
    app.listen(format!("0.0.0.0:{}", port)).await?;
    Ok(())
}
