mod error;
mod gamma;
mod opt;
mod redis;
mod token;
mod util;

#[macro_use]
extern crate log;

use async_std::fs;
use chrono::{DateTime, Utc};
use data_encoding::BASE64;
use dotenv::dotenv;
use http_types::headers::HeaderValue;
use jsonwebtoken::EncodingKey;
use mobc::{Connection, Pool};
use mobc_redis::{redis::Client, RedisConnectionManager};
use pkcs8::{FromPrivateKey, PublicKeyDocument, ToPublicKey};
use rsa::RsaPrivateKey;
use serde::{Deserialize, Serialize, Serializer};
use std::sync::Arc;
use tide::security::{CorsMiddleware, Origin};
use tide::{Body, Request, Response};

use crate::error::Error;
use crate::gamma::{Credentials, User};
use crate::opt::Opt;
use crate::token::{new_token, stringify_access_scopes, Access, Action};
use crate::util::{hash_token, random_string, to_vec};

pub type RedisPool = Pool<RedisConnectionManager>;
pub type RedisConnection = Connection<RedisConnectionManager>;

#[derive(Clone)]
pub struct State {
    pub_key: Arc<PublicKeyDocument>,
    jwt_enc_key: Arc<EncodingKey>,
    gamma_uri: Arc<String>,
    opt: Arc<Opt>,
    redis_pool: RedisPool,
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

    let client = Client::open(opt.redis_host.clone()).unwrap();
    let manager = RedisConnectionManager::new(client);
    let redis_pool = Pool::builder().build(manager);

    let state = State {
        pub_key: Arc::new(priv_key.to_public_key_der()?),
        jwt_enc_key: Arc::new(jwt_enc_key),
        gamma_uri: Arc::new("https://gamma.chalmers.it".to_string()),
        opt: Arc::new(opt),
        redis_pool,
    };

    let mut app = tide::with_state(state);
    app.with(
        CorsMiddleware::new()
            .allow_methods("GET, POST, OPTIONS".parse::<HeaderValue>().unwrap())
            .allow_origin(Origin::from("*"))
            .allow_credentials(false),
    );
    app.at("/token").get(issue_token).post(refresh_token);
    app.listen("0.0.0.0:3000").await?;
    Ok(())
}

impl From<(&str, &str)> for Credentials {
    fn from((user, pass): (&str, &str)) -> Self {
        Credentials {
            username: user.to_string(),
            password: pass.to_string(),
        }
    }
}

async fn basic_auth(req: &Request<State>) -> Result<Option<User>, tide::Response> {
    let state = req.state();

    fn text_response(status: u16, msg: String) -> tide::Response {
        Response::builder(status)
            .body(Body::from_string(msg))
            .build()
    }

    fn unauthorized(msg: &str) -> tide::Response {
        text_response(401, format!("Unauthorized:\n{}", msg))
    }

    fn bad_request(msg: &str) -> tide::Response {
        warn!("Basic auth: Bad Request: {}", msg);
        text_response(400, format!("Bad Request:\n{}", msg))
    }

    /// Convert an Option or a Result into a Result<T, BadRequest>
    fn ok_or_bad<T, I: IntoIterator<Item = T>>(msg: &str, iter: I) -> Result<T, tide::Response> {
        iter.into_iter().next().ok_or_else(|| bad_request(msg))
    }

    match req.header("Authorization") {
        Some(header) => {
            let value = header.last();
            let (kind, token) = ok_or_bad(
                "Invalid authorization header format",
                value.as_str().split_once(" "),
            )?;

            if kind != "Basic" {
                return Err(bad_request("Authorization header format must be Basic"));
            }

            let credentials = ok_or_bad(
                "Basic auth token must be Base64",
                BASE64.decode(token.trim().as_bytes()),
            )?;
            let credentials = ok_or_bad(
                "Basic auth token must be valid utf-8",
                std::str::from_utf8(&credentials),
            )?;

            let (user, pass) = ok_or_bad(
                "Basic auth token must contain ':'",
                credentials.split_once(":"),
            )?;

            let user = match gamma::login(&state.opt, &(user, pass).into()).await {
                Ok(user) => user,
                Err(msg) => {
                    warn!("Gamma Error: {}", msg);
                    return Err(unauthorized("Invalid credentials"));
                }
            };

            Ok(Some(user))
        }
        None => Ok(None),
    }
}

async fn issue_token(req: Request<State>) -> tide::Result {
    let params = req.query::<IssueTokenRequest>()?;
    let state = req.state();

    info!(r#"GET "/token". params: {:?}"#, params);

    let user = match basic_auth(&req).await {
        Ok(user) => user,
        Err(resp) => return Ok(resp),
    };

    let refresh_token = match (&user, params.offline_token) {
        (Some(user), Some(true)) => {
            let refresh_token = random_string(64);
            redis::set(
                &state.redis_pool,
                &hash_token(&refresh_token, &state.opt),
                &user.cid,
            )
            .await?;
            Some(refresh_token)
        }
        _ => None,
    };

    let scope = validate_scope(user.as_ref(), &state.opt, params.scope);

    let token = new_token(
        to_vec(scope),
        params.account.unwrap_or_default(),
        params.service,
        state,
    )?;

    let body = IssueTokenResponse {
        token,
        expires_in: Some(state.opt.token_expires),
        refresh_token,
        ..Default::default()
    };

    Ok(Response::builder(200).body(Body::from_json(&body)?).build())
}

async fn refresh_token(mut req: Request<State>) -> tide::Result {
    let params = req.body_form::<OAuth2TokenRequest>().await.unwrap();
    let state = req.state();

    info!(r#"POST "/token". params: {:?}"#, params);

    match params.grant_type {
        GrantType::RefreshToken => {
            // TODO: don't unwrap
            let refresh_token = params.refresh_token.unwrap();
            // lookup hash of token from redis
            let token_hash = hash_token(&refresh_token, &state.opt);
            let username = redis::get(&state.redis_pool, &token_hash).await?;
            let user = gamma::get_user(&state.opt, &username).await?;

            let scope = validate_scope(Some(&user), &state.opt, params.scope.clone());
            let scope = to_vec(scope);
            let scope_string = stringify_access_scopes(&scope);

            let access_token = new_token(scope, username, params.service, state)?;

            let body = OAuth2TokenResponse {
                access_token,
                scope: scope_string,
                expires_in: Some(state.opt.token_expires),
                refresh_token: match params.access_type {
                    Some(AccessType::Offline) => Some(refresh_token),
                    _ => None,
                },
                issued_at: None,
            };
            Ok(Response::builder(200).body(Body::from_json(&body)?).build())
        }
    }
}

fn validate_scope(user: Option<&User>, opt: &Opt, scope: Option<Access>) -> Option<Access> {
    let can_write = user
        .iter()
        .any(|user| user.is_member_of(&opt.priviliged_groups));

    if can_write {
        scope
    } else {
        if let Some(access) = scope {
            Some(Access {
                actions: access
                    .actions
                    .into_iter()
                    .filter(|&action| action != Action::Push)
                    .collect(),
                ..access
            })
        } else {
            None
        }
    }
}

#[derive(Debug, Deserialize)]
struct IssueTokenRequest {
    service: String,
    offline_token: Option<bool>,
    client_id: Option<String>,
    // TODO: should probably be a Vec
    scope: Option<Access>,
    account: Option<String>,
}

#[derive(Debug, Default, Serialize)]
struct IssueTokenResponse {
    token: String,
    expires_in: Option<u32>,
    #[serde(
        serialize_with = "utc_date_time_to_rfc3339",
        skip_serializing_if = "Option::is_none"
    )]
    issued_at: Option<DateTime<Utc>>,
    refresh_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OAuth2TokenRequest {
    grant_type: GrantType,
    service: String,
    client_id: String,
    access_type: Option<AccessType>,
    // TODO: should probably be a Vec
    scope: Option<Access>,
    refresh_token: Option<String>,
    username: Option<String>,
    password: Option<String>,
}

#[derive(Debug, Serialize)]
struct OAuth2TokenResponse {
    access_token: String,
    scope: String,
    expires_in: Option<u32>,
    #[serde(
        serialize_with = "utc_date_time_to_rfc3339",
        skip_serializing_if = "Option::is_none"
    )]
    issued_at: Option<DateTime<Utc>>,
    refresh_token: Option<String>,
}

#[derive(Debug, Deserialize)]
enum GrantType {
    #[serde(rename = "refresh_token")]
    RefreshToken,
}

#[derive(Debug, Deserialize)]
enum AccessType {
    #[serde(rename = "online")]
    Online,

    #[serde(rename = "offline")]
    Offline,
}

fn utc_date_time_to_rfc3339<S>(
    date_time: &Option<DateTime<Utc>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match date_time {
        Some(date_time) => serializer.serialize_str(&date_time.to_rfc3339()),
        None => unreachable!(),
    }
}
