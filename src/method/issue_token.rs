use crate::{
    gamma::{self, User},
    redis, response,
    token::{new_token, validate_scope, Access},
    util::{hash_token, random_string, to_vec, utc_date_time_to_rfc3339},
    State,
};
use chrono::{DateTime, Utc};
use data_encoding::BASE64;
use serde::{Deserialize, Serialize};
use tide::{Body, Request, Response};

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

pub async fn handler(req: Request<State>) -> tide::Result {
    let params = match req.query::<IssueTokenRequest>() {
        Ok(params) => params,
        Err(_) => return Ok(response::bad_request("Invalid request data format")),
    };
    let state = req.state();

    info!(r#"GET "/token". params: {:?}"#, params);

    let user = match basic_auth(&req).await {
        Ok(user) => user,
        Err(resp) => return Ok(resp),
    };

    let refresh_token = match (&user, params.offline_token) {
        (Some(user), Some(true)) => {
            let refresh_token = random_string(64);
            redis::set(state, &hash_token(&refresh_token, &state.opt), &user.cid).await?;
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

async fn basic_auth(req: &Request<State>) -> Result<Option<User>, tide::Response> {
    let state = req.state();

    /// Convert an Option or a Result into a Result<T, BadRequest>
    fn ok_or_bad<T, I: IntoIterator<Item = T>>(msg: &str, iter: I) -> Result<T, tide::Response> {
        iter.into_iter()
            .next()
            .ok_or_else(|| response::bad_request(msg))
    }

    match req.header("Authorization") {
        Some(header) => {
            let value = header.last();
            let (kind, token) = ok_or_bad(
                "Invalid authorization header format",
                value.as_str().split_once(" "),
            )?;

            if kind != "Basic" {
                return Err(response::bad_request(
                    "Authorization header format must be Basic",
                ));
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
                    return Err(response::unauthorized("Invalid credentials"));
                }
            };

            Ok(Some(user))
        }
        None => Ok(None),
    }
}
