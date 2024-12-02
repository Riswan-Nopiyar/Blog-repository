use actix_web::{web, App, HttpServer, Responder, HttpResponse, middleware::Logger};
use actix_cors::Cors;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use std::path::Path;
use serde::{Deserialize, Serialize};
use actix_rt::System;
use actix_web::dev::ServiceRequest;
use actix_web::http::header::{CONTENT_TYPE, AUTHORIZATION};
use actix_web::middleware::ErrorHandlers;
use actix_web::http::StatusCode;
use actix_web::error::ErrorInternalServerError;
use std::time::Duration;

#[derive(Serialize, Deserialize)]
struct Greeting {
    message: String,
}

#[derive(Deserialize)]
struct GreetingRequest {
    name: String,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    
    let ssl_acceptor = create_ssl_acceptor();
    let cors = configure_cors();

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .wrap(cors)
            .wrap(ErrorHandlers::new().handler(StatusCode::INTERNAL_SERVER_ERROR, error_handler))
            .route("/", web::get().to(home))
            .route("/greet", web::post().to(greet))
            .route("/health", web::get().to(health_check))
            .route("/users", web::get().to(get_users))
            .route("/error", web::get().to(generate_error))
    })
    .bind_rustls("0.0.0.0:443", ssl_acceptor)?
    .run()
    .await
}

async fn home() -> impl Responder {
    HttpResponse::Ok().json(Greeting {
        message: String::from("Welcome to Nopiyar Server!"),
    })
}

async fn greet(greeting: web::Json<GreetingRequest>) -> impl Responder {
    HttpResponse::Ok().json(Greeting {
        message: format!("Hello, {}!", greeting.name),
    })
}

async fn health_check() -> impl Responder {
    HttpResponse::Ok().json(Greeting {
        message: String::from("Server is healthy!"),
    })
}

async fn get_users() -> impl Responder {
    let users = vec![
        "Alice".to_string(),
        "Bob".to_string(),
        "Charlie".to_string(),
    ];
    HttpResponse::Ok().json(users)
}

async fn generate_error() -> impl Responder {
    Err(ErrorInternalServerError("Something went wrong"))
}

fn error_handler(_req: &ServiceRequest, _err: actix_web::error::Error) -> HttpResponse {
    HttpResponse::InternalServerError().json("An unexpected error occurred")
}

fn create_ssl_acceptor() -> SslAcceptor {
    SslAcceptor::mozilla_intermediate(SslMethod::tls())
        .unwrap()
        .set_private_key_file(Path::new("path/to/private.key"), SslFiletype::PEM)
        .unwrap()
        .set_certificate_chain_file(Path::new("path/to/certificate.pem"))
        .unwrap()
}

fn configure_cors() -> Cors {
    Cors::default()
        .allowed_origin("https://www.nopiyar.my.id")
        .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
        .allowed_headers(vec![CONTENT_TYPE, AUTHORIZATION])
        .max_age(3600)
}

fn request_timeout() -> Duration {
    Duration::from_secs(30)
}
