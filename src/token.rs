use crate::util::{generate_key_id, random_string, split_array};
use crate::State;
use chrono::serde::ts_seconds;
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{Algorithm, Header};
use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize};
use std::{
    convert::{TryFrom, TryInto},
    fmt,
};

/// Example claim (from https://docs.docker.com/registry/spec/auth/jwt/)
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

#[derive(Debug, Clone, Serialize)]
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
        let [res_type, name, actions] = split_array(&value, ':').ok_or("Not enough parts")?;

        let actions = actions
            .split(",")
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

impl<'de> Deserialize<'de> for Access {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AccessVisitor;

        impl<'de> Visitor<'de> for AccessVisitor {
            type Value = Access;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("repository:nginx:push,pull") // TODO
            }

            fn visit_str<E>(self, value: &str) -> Result<Access, E>
            where
                E: de::Error,
            {
                value.try_into().map_err(|e| {
                    error!("Access deserialize error: {}", e);
                    todo!("Access deserialize error")
                })
            }
        }

        deserializer.deserialize_identifier(AccessVisitor)
    }

    fn deserialize_in_place<D>(deserializer: D, place: &mut Self) -> Result<(), D::Error>
    where
        D: Deserializer<'de>,
    {
        // Default implementation just delegates to `deserialize` impl.
        *place = Deserialize::deserialize(deserializer)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize)]
pub enum Action {
    #[serde(rename = "push")]
    Push,

    #[serde(rename = "pull")]
    Pull,
}

impl TryFrom<&str> for Action {
    type Error = &'static str;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "pull" => Ok(Self::Pull),
            "push" => Ok(Self::Push),
            _ => Err("Must be push or pull"),
        }
    }
}

pub fn new_token(access: Vec<Access>, username: String, service: String, state: &State) -> String {
    let now = Utc::now();

    let header = Header {
        alg: Algorithm::RS256,
        kid: Some(generate_key_id(
            &state.priv_key.public_key_to_der().unwrap(),
        )), // TODO
        ..Header::default()
    };

    let claims = Claims {
        iss: "auth.docker.chalmers.it".to_string(),
        sub: username,
        aud: service,
        exp: now + Duration::seconds(state.opt.token_expires as i64),
        nbf: now,
        iat: now,
        jti: random_string(16), // TODO
        access,
    };

    jsonwebtoken::encode(&header, &claims, &state.jwt_enc_key).expect("encode JWT")
}
