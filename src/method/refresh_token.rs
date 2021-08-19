use crate::{
    gamma, redis, response,
    token::{new_token, stringify_access_scopes, validate_scope, Access},
    util::{hash_token, to_vec, utc_date_time_to_rfc3339},
    State,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tide::{Body, Request, Response};

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

pub async fn handler(mut req: Request<State>) -> tide::Result {
    let params = match req.body_form::<OAuth2TokenRequest>().await {
        Ok(params) => params,
        Err(_) => return Ok(response::bad_request("Invalid request data format")),
    };

    let state = req.state();

    info!(r#"POST "/token". params: {:?}"#, params);

    match params.grant_type {
        GrantType::RefreshToken => {
            let refresh_token = match params.refresh_token {
                Some(token) => token,
                None => return Ok(response::bad_request("Missing refresh token")),
            };

            // lookup hash of token from redis
            let token_hash = hash_token(&refresh_token, &state.opt);
            let username = match redis::get(state, &token_hash).await? {
                Some(username) => username,
                None => {
                    // refresh token is likely expired
                    return Ok(response::unauthorized("Invalid or expired token"));
                }
            };
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
