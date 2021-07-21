use anyhow::Error;

#[derive(Debug)]
pub struct Opt {
    /// Example: https://gamma.chalmers.it
    pub gamma_uri: String,

    /// Example: "auth.docker.chalmers.it"
    pub issuer: String,

    /// Number of seconds that an access token should be valid for
    pub token_expires: u32,
}

impl Opt {
    pub fn from_env() -> Result<Opt, Error> {
        let env = |name| std::env::var(name).map_err(|e| Error::msg(format!("{}: {}", name, e)));

        Ok(Opt {
            issuer: env("AUTH_ISSUER")?,
            gamma_uri: env("GAMMA_HOST")?,
            token_expires: env("TOKEN_EXPIRES")?.parse()?,
        })
    }
}
