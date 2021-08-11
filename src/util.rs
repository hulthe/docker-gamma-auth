use data_encoding::{BASE32, BASE64};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use sha2::{Digest, Sha256};

use crate::opt::Opt;

pub fn split_array<const N: usize>(s: &str, pat: char) -> Option<[&str; N]> {
    let mut arr = [""; N];

    let mut split = s.splitn(N, pat);
    for i in 0..N {
        arr[i] = split.next()?;
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

/// Convert an IntoIterator to a Vec
pub fn to_vec<T, I: IntoIterator<Item = T>>(i: I) -> Vec<T> {
    i.into_iter().collect()
}
