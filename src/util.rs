use rand::{distributions::Alphanumeric, thread_rng, Rng, RngCore};

pub fn split_array<const N: usize>(s: &str, pat: char) -> Option<[&str; N]> {
    let mut arr = [""; N];

    let mut split = s.split(pat);
    for i in 0..N {
        arr[i] = split.next()?;
    }

    Some(arr)
}

/// Generate libtrust key id from a DER public key
pub fn generate_key_id(key: &[u8]) -> String {
    use data_encoding::BASE32;
    use ring::digest::{digest, SHA256};

    const N: usize = 240 / 8;

    let digest = digest(&SHA256, key);
    let digest = &digest.as_ref()[..N]; // trunkate to 240 bits

    let b32 = BASE32.encode(digest);

    b32.chars()
        .collect::<Vec<char>>()
        .chunks(4)
        .map(|c| c.iter().collect::<String>())
        .reduce(|a, b| [a, b].join(":"))
        .unwrap()
}

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0; len];
    thread_rng().fill_bytes(&mut bytes);
    bytes
}

pub fn random_string(len: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}
