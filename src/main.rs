#[macro_use]
extern crate warp;

#[macro_use]
extern crate derive_more;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate log;

use warp::http::StatusCode;
use warp::Filter;

mod api;
mod config;
mod data;
mod error;
mod login;
mod oauth;

pub use error::{Error, Result};
pub use oauth::OAuthEndpoint;

fn main() {
    simple_logger::init_with_level(log::Level::Info).unwrap();
    match serve() {
        Err(e) => {
            error!("Service error occurred: {}", e);
            std::process::exit(2)
        }
        _ => std::process::exit(0),
    }
}

fn configure() -> Result<()> {
    let f = std::fs::File::open("config.yml")?;
    let c: config::Config = serde_yaml::from_reader(f)?;
    login::set_authenticator(c.login);
    OAuthEndpoint::add_clients(c.oauth.clients);
    Ok(())
}

fn serve() -> Result<()> {
    configure()?;
    let log = warp::log("oauth");

    let get_routes = warp::get2().and(api::get_index().or(api::get_authorize()));
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
    Ok(())
}
