//! Shorthand http response

use tide::{Body, Response};

pub fn plaintext(status: u16, msg: String) -> tide::Response {
    Response::builder(status)
        .body(Body::from_string(msg))
        .build()
}

pub fn unauthorized(msg: &str) -> tide::Response {
    plaintext(401, format!("Unauthorized:\n{}", msg))
}

pub fn bad_request(msg: &str) -> tide::Response {
    warn!("Basic auth: Bad Request: {}", msg);
    plaintext(400, format!("Bad Request:\n{}", msg))
}
