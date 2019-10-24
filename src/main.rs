#[macro_use]
extern crate warp;

#[macro_use]
extern crate derive_more;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate log;

use warp::{http::StatusCode, Filter};

mod api;
mod args;
mod data;
mod error;
mod login;
mod oauth;

pub use {
    args::CONFIG,
    error::{Error, Result},
    oauth::OAuthEndpoint,
};

fn main() {
    simple_logger::init_with_level(CONFIG.general.log).unwrap();
    match serve() {
        Err(e) => {
            error!("Service error occurred: {}", e);
            std::process::exit(2)
        }
        _ => std::process::exit(0),
    }
}

fn configure() -> Result<()> {
    OAuthEndpoint::add_clients();
    Ok(())
}

fn serve() -> Result<()> {
    configure()?;
    let log = warp::log("oauth");

    let get_routes = warp::get2().and(
        api::get_authorize()
            .or(api::get_authenticate())
            .or(api::get_userdetail()),
    );

    let post_routes = warp::post2().and(
        api::post_authorize()
            .or(api::post_refresh())
            .or(api::post_token()),
    );

    let serve_files = warp::fs::dir("www/");

    let routes = get_routes
        .or(post_routes)
        .or(serve_files)
        .or(warp::any().map(|| StatusCode::from_u16(404).unwrap()));

    warp::serve(routes.with(log)).run(([0, 0, 0, 0], 3030));
    data::clean()?;
    Ok(())
}
