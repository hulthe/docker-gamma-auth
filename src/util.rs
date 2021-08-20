use crate::opt::Opt;
use chrono::{DateTime, Utc};
use data_encoding::{BASE32, BASE64};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use serde::Serializer;
use sha2::{Digest, Sha256};

pub fn split_array<const N: usize>(s: &str, pat: char) -> Option<[&str; N]> {
    let mut arr = [""; N];

    let mut split = s.splitn(N, pat);
    for part in arr.iter_mut() {
        *part = split.next()?;
    }

    Some(arr)
}

/// Generate libtrust key id from a DER public key
pub fn generate_key_id(key: &[u8]) -> String {
    const N: usize = 240 / 8;

    let digest = Sha256::new().chain(key).finalize();
    let digest = &digest[..N]; // truncate to 240 bits

    let b32 = BASE32.encode(digest);

    b32.chars()
        .collect::<Vec<char>>()
        .chunks(4)
        .map(|c| c.iter().collect::<String>())
        .reduce(|a, b| [a, b].join(":"))
        .unwrap()
}

pub fn hash_token(token: &str, _opt: &Opt) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"seed");
    hasher.update(token.as_bytes());
    let digest = hasher.finalize();
    BASE64.encode(&digest)
}

pub fn random_string(len: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

/// Serialize a datetime as RFC 3339
pub fn utc_date_time_to_rfc3339<S>(
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
