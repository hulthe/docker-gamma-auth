use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use surf::{Body, Client, Response};

use crate::opt::Opt;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct User {
    pub cid: String,
    pub groups: Vec<Group>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Group {
    pub name: String,

    #[serde(rename = "superGroup")]
    pub super_group: SuperGroup,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SuperGroup {
    pub name: String,
}

fn check_status(resp: &Response) -> Result<(), anyhow::Error> {
    if resp.status().is_server_error() {
        Err(anyhow!("Gamma Error: {}", resp.status()))
    } else if resp.status().is_client_error() {
        Err(anyhow!("Invalid credentials"))
    } else {
        Ok(())
    }
}

pub(crate) async fn login(opt: &Opt, credentials: &Credentials) -> Result<User, anyhow::Error> {
    let mut client = Client::new().with(surf_cookie_middleware::CookieMiddleware::new());
    let login_uri = format!("{}{}", opt.gamma_uri, "/api/login");
    let login_resp = client
        .post(&login_uri)
        .body(Body::from_form(credentials).expect("infallible"))
        .send()
        .await
        .map_err(|e| anyhow!("gamma: login failed: {}", e))?;

    info!(
        r#"POST "{}" user={} status={:?}"#,
        login_uri,
        credentials.username,
        login_resp.status()
    );

    check_status(&login_resp)?;

    get_me(&mut client, opt, &credentials.username).await
}

async fn get_me(client: &mut Client, opt: &Opt, username: &str) -> Result<User, anyhow::Error> {
    let me_uri = format!("{}{}", opt.gamma_uri, "/api/users/me");
    let mut me_resp = client
        .get(&me_uri)
        .send()
        .await
        .map_err(|e| anyhow!("gamma: get user info failed: {}", e))?;

    info!(
        r#"GET "{}" user={} status={:?}"#,
        me_uri,
        username,
        me_resp.status()
    );

    check_status(&me_resp)?;

    let user: User = me_resp
        .body_json()
        .await
        .map_err(|e| anyhow!("gamma: failed to deserialize json: {}", e))?;

    Ok(user)
}

pub(crate) async fn get_user(opt: &Opt, username: &str) -> Result<User, anyhow::Error> {
    let client = Client::default();
    let user_uri = format!("{}{}{}", opt.gamma_uri, "/api/users/", username);
    let mut user_resp = client
        .get(&user_uri)
        .header("Authorization", format!("pre-shared {}", opt.gamma_api_key))
        .send()
        .await
        .map_err(|e| anyhow!("gamma: get user info failed: {}", e))?;

    info!(
        r#"GET "{}" user={} status={:?}"#,
        user_uri,
        username,
        user_resp.status()
    );

    check_status(&user_resp)?;

    let user: User = user_resp.body_json().await.map_err(|e| {
        error!("{}", e);
        anyhow!("gamma: failed to deserialize json: {}", e)
    })?;

    Ok(user)
}

impl User {
    pub fn is_member_of<T: AsRef<str>>(&self, allowed: &[T]) -> bool {
        let mut groups = self
            .groups
            .iter()
            .flat_map(|group| [&group.name, &group.super_group.name]);

        groups.any(|group| {
            allowed
                .iter()
                .any(|allowed| allowed.as_ref() == group.as_str())
        })
    }
}
