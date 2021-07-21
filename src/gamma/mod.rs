//pub mod cache;

use serde::{Deserialize, Serialize};
use surf::{Body, Client, Response};

use crate::opt::Opt;

#[derive(Clone, PartialEq, Eq, Hash, Serialize)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Deserialize)]
pub struct User {
    pub cid: String,
    pub username: String,
    pub groups: Vec<Group>,
}

#[derive(Clone, Deserialize)]
pub struct Group {
    pub name: String,

    #[serde(rename = "superGroup")]
    pub super_group: SuperGroup,
}

#[derive(Clone, Deserialize)]
pub struct SuperGroup {
    pub name: String,
}

fn check_status(resp: &Response) -> Result<(), String> {
    if resp.status().is_server_error() {
        Err(format!("Gamma Error: {}", resp.status()))
    } else if resp.status().is_client_error() {
        Err("Invalid credentials".to_string())
    } else {
        Ok(())
    }
}

pub(crate) async fn login(
    client: &mut Client,
    opt: &Opt,
    credentials: &Credentials,
) -> Result<User, String> {
    let login_uri = format!("{}{}", opt.gamma_uri, "/api/login");
    let login_resp = client
        .post(&login_uri)
        .body(Body::from_form(credentials).expect("infallible"))
        .send()
        .await
        .map_err(|e| format!("gamma: login failed: {}", e))?;

    debug!(
        "gamma: tried logging in. user={}, uri={}, response={:?}",
        credentials.username, login_uri, login_resp
    );

    check_status(&login_resp)?;

    get_me(client, opt, &credentials.username).await
}

pub(crate) async fn get_me(client: &mut Client, opt: &Opt, username: &str) -> Result<User, String> {
    let me_uri = format!("{}{}", opt.gamma_uri, "/api/users/me");
    let mut me_resp = client
        .get(&me_uri)
        .send()
        .await
        .map_err(|e| format!("gamma: get user info failed: {}", e))?;

    debug!(
        "gamma: tried getting user info. user={}, uri={}, response={}",
        username,
        me_uri.as_str(),
        format!("{:?}", me_resp).as_str(),
    );

    check_status(&me_resp)?;

    let user: User = me_resp
        .body_json()
        .await
        .map_err(|e| format!("gamma: failed to deserialize json: {}", e))?;

    Ok(user)
}
