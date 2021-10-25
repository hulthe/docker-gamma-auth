use anyhow::{anyhow, Error};

#[derive(Debug)]
pub struct Opt {
    pub port: u16,

    /// Example: https://gamma.chalmers.it
    pub gamma_uri: String,

    /// Example: "auth.docker.chalmers.it"
    pub issuer: String,

    /// Number of seconds that an access token should be valid for
    pub token_expires: u32,

    /// Number of seconds that a refresh token should be valid for
    pub refresh_token_expires: u32,

    /// Example: redis://localhost:6379
    pub redis_host: String,

    /// Gamma API key
    pub gamma_api_key: String,

    /// The gamma groups that have push-access
    pub priviliged_groups: Vec<String>,

    /// Tokens that are authorized
    pub machine_tokens: Vec<String>,
}

impl Opt {
    pub fn from_env() -> Result<Opt, Error> {
        let env = |name| std::env::var(name).map_err(|e| Error::msg(anyhow!("{}: {}", name, e)));

        Ok(Opt {
            port: env("PORT")?.parse()?,
            issuer: env("AUTH_ISSUER")?,
            gamma_uri: env("GAMMA_HOST")?,
            token_expires: env("TOKEN_EXPIRES")?.parse()?,
            refresh_token_expires: env("REFRESH_TOKEN_EXPIRES")?.parse()?,
            redis_host: env("REDIS_HOST")?,
            gamma_api_key: env("GAMMA_API_KEY")?,
            priviliged_groups: env("PRIVILEGED_GROUPS")?
                .split_whitespace()
                .map(|s| s.to_string())
                .collect(),
            machine_tokens: env("MACHINE_TOKENS")?
                .split_whitespace()
                .map(|s| s.to_string())
                .collect(),
        })
    }
}
