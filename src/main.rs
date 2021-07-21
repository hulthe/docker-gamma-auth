mod gamma;
mod opt;
mod token;
mod util;

#[macro_use]
extern crate log;

use async_std::fs;
use chrono::{DateTime, Utc};
use dotenv::dotenv;
use jsonwebtoken::EncodingKey;
use openssl::{pkey::Private, rsa::Rsa};
use serde::{Deserialize, Serialize, Serializer};
use std::sync::Arc;
use tide::{Body, Request, Response};

use crate::opt::Opt;
use crate::token::{new_token, Access};

#[derive(Clone)]
pub struct State {
    priv_key: Arc<Rsa<Private>>,
    jwt_enc_key: Arc<EncodingKey>,
    gamma_uri: Arc<String>,
    opt: Arc<Opt>,
}

#[async_std::main]
async fn main() -> tide::Result<()> {
    dotenv().ok();
    env_logger::init();

    let pem = fs::read_to_string("certs/RootCA.key")
        .await
        .expect("read cert");

    let priv_key = Rsa::private_key_from_pem(pem.as_bytes()).expect("parse pem");
    let jwt_enc_key = EncodingKey::from_rsa_pem(pem.as_bytes()).expect("parse pem");

    let state = State {
        priv_key: Arc::new(priv_key),
        jwt_enc_key: Arc::new(jwt_enc_key),
        gamma_uri: Arc::new("https://gamma.chalmers.it".to_string()),
        opt: Arc::new(Opt::from_env()?),
    };

    let mut app = tide::with_state(state);
    app.at("/token").get(issue_token).post(refresh_token);
    app.listen("0.0.0.0:3000").await?;
    Ok(())
}

async fn issue_token(req: Request<State>) -> tide::Result {
    let params = req.query::<IssueTokenRequest>()?;
    let state = req.state();

    let token = new_token(
        params.scope.iter().cloned().collect(),
        params.account.unwrap_or("".to_string()),
        params.service,
        state,
    );

    info!("new token: {}", token);

    let body = TokenResponse {
        token,
        expires_in: Some(state.opt.token_expires), // Seconds TODO: config
        refresh_token: None,                       // TODO:
        ..Default::default()
    };

    Ok(Response::builder(200)
        .body(Body::from_json(&body).unwrap())
        .build())
}

async fn refresh_token(mut req: Request<State>) -> tide::Result {
    let params = req.body_form::<OAuth2TokenRequest>().await.unwrap();
    let state = req.state();
    match params.grant_type {
        GrantType::RefreshToken => {
            let refresh_token = params.refresh_token.unwrap();
            let token = new_token(
                params.scope.iter().cloned().collect(),
                // TODO: params.account.unwrap_or("".to_string()),
                "124".to_string(),
                params.service,
                state,
            );

            info!("new token: {}", token);

            let body = TokenResponse {
                token,
                expires_in: Some(state.opt.token_expires), // Seconds TODO: config
                refresh_token: match params.access_type {
                    Some(AccessType::Offline) => Some(refresh_token),
                    _ => None,
                },
                ..Default::default()
            };
            Ok(Response::builder(200)
                .body(Body::from_json(&body).unwrap())
                .build())
        }
    }
}

#[derive(Debug, Deserialize)]
struct IssueTokenRequest {
    service: String,
    offline_token: Option<bool>,
    client_id: Option<String>,
    scope: Option<Access>,
    account: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OAuth2TokenRequest {
    grant_type: GrantType,
    service: String,
    client_id: String,
    access_type: Option<AccessType>,
    scope: Option<Access>,
    refresh_token: Option<String>,
    username: Option<String>,
    password: Option<String>,
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

#[derive(Debug, Default, Serialize)]
struct TokenResponse {
    token: String,
    expires_in: Option<u32>,
    #[serde(
        serialize_with = "utc_date_time_to_rfc3339",
        skip_serializing_if = "Option::is_none"
    )]
    issued_at: Option<DateTime<Utc>>,
    refresh_token: Option<String>,
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
