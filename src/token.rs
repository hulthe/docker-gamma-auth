use crate::{
    error::Error,
    gamma::User,
    opt::Opt,
    util::{generate_key_id, random_string, split_array},
    State,
};
use chrono::serde::ts_seconds;
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{Algorithm, Header};
use serde::Serialize;
use std::convert::TryFrom;

/// Example claim (from <https://docs.docker.com/registry/spec/auth/jwt/>)
/// ```json
/// {
///     "iss": "auth.docker.com",
///     "sub": "jlhawn",
///     "aud": "registry.docker.com",
///     "exp": 1415387315,
///     "nbf": 1415387015,
///     "iat": 1415387015,
///     "jti": "tYJCO1c6cnyy7kAn0c7rKPgbV1H1bFws",
///     "access": [
///         {
///             "type": "repository",
///             "name": "samalba/my-app",
///             "actions": [
///                 "pull",
///                 "push"
///             ]
///         }
///     ]
/// }
/// ```
#[derive(Debug, Serialize)]
struct Claims {
    /// The issuer of the token, typically the fqdn of the authorization server.
    pub iss: String,

    /// The subject of the token; the name or id of the client which requested it. This should be empty (`""`) if the client did not authenticate.
    pub sub: String,

    /// The intended audience of the token; the name or id of the service which will verify the token to authorize the client/subject.
    pub aud: String,

    /// The token should only be considered valid up to this specified date and time.
    #[serde(with = "ts_seconds")]
    pub exp: DateTime<Utc>,

    /// The token should not be considered valid before this specified date and time.
    #[serde(with = "ts_seconds")]
    pub nbf: DateTime<Utc>,

    /// Specifies the date and time which the Authorization server generated this token.
    #[serde(with = "ts_seconds")]
    pub iat: DateTime<Utc>,

    /// A unique identifier for this token. Can be used by the intended audience to prevent replays of the token.
    pub jti: String,

    /// An array of access entry objects.
    pub access: Vec<Access>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Access {
    /// The type of resource hosted by the service.
    #[serde(rename = "type")]
    pub res_type: String,

    /// The name of the resource of the given type hosted by the service.
    pub name: String,

    /// An array of strings which give the actions authorized on this resource.
    pub actions: Vec<Action>,
}

impl TryFrom<&str> for Access {
    type Error = &'static str;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        // examples:
        //  repository:nginx:push,pull
        //  registry:catalog:*
        let [res_type, name, actions] = split_array(value, ':').ok_or("Not enough parts")?;

        let actions = actions
            .split(',')
            .map(TryFrom::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_e| "Invalid actions")?;

        Ok(Access {
            res_type: res_type.to_string(),
            name: name.to_string(),
            actions,
        })
    }
}

/// A kind of action to perform on a resource
///
/// *NOTE:* The documentation on this type is severely lacking. It seems to be just an arbitrary
/// string. The variants represents the strings that we've identified, but there is likely more of
/// them.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum Action {
    /// Push-access to a repository
    #[serde(rename = "push")]
    Push,

    /// Pull-access to a repository
    #[serde(rename = "pull")]
    Pull,

    /// Delete-access to a repository
    #[serde(rename = "delete")]
    Delete,

    /// This string seems to indicate that no other action is applicable. It is found in the
    /// `registry:catalog:*` scope, which grants access to reading the global repository catalog.
    #[serde(rename = "*")]
    Star,
}

impl TryFrom<&str> for Action {
    type Error = &'static str;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "pull" => Ok(Self::Pull),
            "push" => Ok(Self::Push),
            "delete" => Ok(Self::Delete),
            "*" => Ok(Self::Star),
            _ => Err("Unrecognized resource scope action"),
        }
    }
}

impl Action {
    /// Whether this action does **not** requires authentication
    pub fn is_unprivileged(&self) -> bool {
        // Actions should be explicitly marked as unprivileged, since they can be granted without
        // any kind of authentication.
        matches!(self, Action::Star | Action::Pull)
    }
}

pub fn new_token(
    access: Vec<Access>,
    username: String,
    service: String,
    state: &State,
) -> Result<String, Error> {
    let now = Utc::now();

    let header = Header {
        alg: Algorithm::RS256,
        kid: Some(generate_key_id((*state.pub_key).as_ref())),
        ..Header::default()
    };

    let claims = Claims {
        iss: state.opt.issuer.clone(),
        sub: username,
        aud: service,
        exp: now + Duration::seconds(state.opt.token_expires as i64),
        nbf: now,
        iat: now,
        jti: random_string(16),
        access,
    };

    Ok(jsonwebtoken::encode(&header, &claims, &state.jwt_enc_key)?)
}

/// ## Resource Scope Grammar: (from <https://github.com/distribution/distribution/blob/6affafd1f030087d88f88841bf66a8abe2bf4d24/docs/spec/auth/scope.md>)
/// scope                   := resourcescope [ ' ' resourcescope ]*
/// resourcescope           := resourcetype  ":" resourcename  ":" action [ ',' action ]*
/// resourcetype            := resourcetypevalue [ '(' resourcetypevalue ')' ]
/// resourcetypevalue       := /[a-z0-9]+/
/// resourcename            := [ hostname '/' ] component [ '/' component ]*
/// hostname                := hostcomponent ['.' hostcomponent]* [':' port-number]
/// hostcomponent           := /([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])/
/// port-number             := /[0-9]+/
/// action                  := /[a-z]*/
/// component               := alpha-numeric [ separator alpha-numeric ]*
/// alpha-numeric           := /[a-z0-9]+/
/// separator               := /[_.]|__|[-]*/
pub mod resource_scopes_str {
    use super::Access;
    use serde::{Deserialize, Deserializer, Serializer};
    use std::convert::TryFrom;

    /// Serialize a datetime as RFC 3339
    pub fn serialize<S>(scopes: &[Access], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let string = scopes
            .iter()
            .map(|access| {
                format!(
                    "{}:{}:{}",
                    access.res_type,
                    access.name,
                    access
                        .actions
                        .iter()
                        .flat_map(serde_json::to_string)
                        .reduce(|a, b| [a, b].join(","))
                        .unwrap_or_default(),
                )
            })
            .reduce(|a, b| [a, b].join(" "))
            .unwrap_or_default();

        serializer.serialize_str(&string)
    }

    /// Deserialize a Vec<Access> from a String according to the resource scope grammar
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Access>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.split(' ')
            .map(Access::try_from)
            .collect::<Result<_, _>>()
            .map_err(serde::de::Error::custom)
    }
}

pub fn validate_scopes(
    scopes: impl IntoIterator<Item = Access>,
    user: Option<&User>,
    opt: &Opt,
) -> Vec<Access> {
    let privileged_user = user
        .iter()
        .any(|user| user.is_member_of(&opt.priviliged_groups));

    scopes
        .into_iter()
        .filter_map(|scope| {
            if privileged_user {
                Some(scope)
            } else {
                let scope = Access {
                    actions: scope
                        .actions
                        .into_iter()
                        .filter(Action::is_unprivileged) // only retain unprivileged actions
                        .collect(),
                    ..scope
                };

                if scope.actions.is_empty() {
                    None
                } else {
                    Some(scope)
                }
            }
        })
        .collect()
}
