use crate::oauth::*;
use std::collections::HashMap;
use warp::{http::HeaderMap, Filter, Rejection};

const COOKIE_NAME: &str = "SID";

pub fn get_index() -> impl Filter<Extract = (&'static str,), Error = Rejection> + Clone {
    warp::path::end()
        .and(warp::header::headers_cloned())
        .and(warp::query::raw())
        .and(warp::cookie::optional(COOKIE_NAME))
        .map(
            |headers: HeaderMap, query: String, cookie: Option<String>| {
                let req = AuthRequest::new(query, headers, None, cookie);
                if resource(req).is_err() {
                    "Not Authorized"
                } else {
                    "Authorized"
                }
            },
        )
}

pub fn get_authorize() -> impl Filter<Extract = (AuthResponse,), Error = Rejection> + Clone {
    path!("authorize")
        .and(warp::header::headers_cloned())
        .and(warp::query::raw())
        .and(warp::cookie::optional(COOKIE_NAME))
        .map(
            |headers: HeaderMap, query: String, cookie: Option<String>| {
                let req = AuthRequest::new(query, headers, None, cookie);
                match authorize(req) {
                    Err(e) => {
                        error!("{}", e);
                        AuthResponse::default()
                    }
                    Ok(a) => a,
                }
            },
        )
}

pub fn post_authorize() -> impl Filter<Extract = (AuthResponse,), Error = Rejection> + Clone {
    path!("authorize")
        .and(warp::body::content_length_limit(1024 * 32))
        .and(warp::body::form())
        .and(warp::header::headers_cloned())
        .and(warp::query::raw())
        .and(warp::cookie::optional(COOKIE_NAME))
        .map(
            |form: HashMap<String, String>,
             headers: HeaderMap,
             query: String,
             cookie: Option<String>| {
                info!("Endpoint hit");
                let req = AuthRequest::new(query, headers, Some(form), cookie);
                authorize(req).unwrap_or_default()
            },
        )
}

pub fn post_token() -> impl Filter<Extract = (AuthResponse,), Error = Rejection> + Clone {
    path!("token")
        .and(warp::body::form())
        .and(warp::header::headers_cloned())
        .and(warp::query::raw())
        .and(warp::cookie::optional(COOKIE_NAME))
        .map(
            |form: HashMap<String, String>,
             headers: HeaderMap,
             query: String,
             cookie: Option<String>| {
                let req = AuthRequest::new(query, headers, Some(form), cookie);
                token(req).unwrap_or_default()
            },
        )
}

pub fn post_refresh() -> impl Filter<Extract = (AuthResponse,), Error = Rejection> + Clone {
    path!("refresh")
        .and(warp::body::form())
        .and(warp::header::headers_cloned())
        .and(warp::query::raw())
        .and(warp::cookie::optional(COOKIE_NAME))
        .map(
            |form: HashMap<String, String>,
             headers: HeaderMap,
             query: String,
             cookie: Option<String>| {
                let req = AuthRequest::new(query, headers, Some(form), cookie);
                refresh(req).unwrap_or_default()
            },
        )
}
