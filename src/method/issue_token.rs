use crate::{
    gamma::{self, User},
    redis, response,
    token::{new_token, validate_scopes, Access},
    util::{hash_token, random_string, utc_date_time_to_rfc3339},
    State,
};
use chrono::{DateTime, Utc};
use data_encoding::BASE64;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use tide::{Body, Request, Response};

#[derive(Debug, Deserialize)]
struct IssueTokenRequest {
    service: String,
    offline_token: Option<bool>,
    client_id: Option<String>,
    account: Option<String>,

    // multiple scopes are specified with multpile `scope=...`-entries in the url query string.
    // serde_qs does not support this kind of encoding so we have to manually deserialize it.
    #[serde(skip)]
    scopes: Vec<Access>,
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
    info!(r#"GET "/token". url: {}"#, req.url());

    // serde_qs doesn't like duplicated keys, so we strip them
    const SCOPE_KEY: &str = "scope";
    let mut stripped_url = req.url().clone();
    stripped_url
        .query_pairs_mut()
        .clear()
        .extend_pairs(req.url().query_pairs().filter(|(k, _)| k != SCOPE_KEY));

    // parse query parameters (except "scope")
    let params: IssueTokenRequest =
        match serde_qs::from_str(stripped_url.query().unwrap_or_default()) {
            Ok(params) => params,
            Err(e) => {
                return Ok(response::bad_request(&format!(
                    "Invalid request data format: {}",
                    e
                )))
            }
        };

    // see comment on IssueTokenRequest::scope
    debug_assert!(params.scopes.is_empty());
    let params = IssueTokenRequest {
        scopes: req
            .url()
            .query_pairs()
            .filter(|(k, _)| k == SCOPE_KEY)
            .flat_map(|(_, v)| Access::try_from(v.as_ref())) /* invalid strings are discarded */
            .collect(),
        ..params
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

    // Filter scopes that the user do not have access to
    let scopes: Vec<Access> = validate_scopes(params.scopes, user.as_ref(), &state.opt);

    let token = new_token(
        scopes,
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
