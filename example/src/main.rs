//! A static file server whose requests can be answered from the kernel.

use hyper_fast_path::{
    OpenObject,
    fast_path::{self, FastPath},
    listener::BeeperListener,
    server,
};
use clap::Parser;
use std::{collections::HashMap, net::SocketAddr, path::PathBuf};
use tokio::net::TcpListener;
use tower_http::{services::ServeDir, trace::TraceLayer};
use tracing_subscriber::EnvFilter;

/// A static file server that can answer its smaller assets from eBPF.
#[derive(Parser)]
#[command(about, long_about = None)]
struct Args {
    /// Disable the eBPF fast path.
    #[arg(long)]
    no_fastpath: bool,

    /// The address to listen on.
    #[arg(short, long, default_value = "127.0.0.1:8080")]
    addr: SocketAddr,

    /// The number of connections the fast path runs on at once.
    #[arg(long, default_value_t = fast_path::DEFAULT_DUMMIES)]
    dummies: usize,
}

/// All assets that are served with the fast path.
fn fastpath_routes(assets_dir: &str) -> HashMap<String, PathBuf> {
    [
        "/1KB.txt",
        "/8KB.txt",
        "/16KB.txt",
        "/32KB.txt",
        "/48KB.txt",
        "/64KB.txt",
        "/128KB.txt",
    ]
    .into_iter()
    .map(|path| {
        let file = PathBuf::from(format!("{assets_dir}{path}"));
        (path.to_string(), file)
    })
    .collect()
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let assets_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/assets");
    let serve_dir = ServeDir::new(assets_dir);

    let app = axum::Router::new()
        .fallback_service(serve_dir)
        .layer(TraceLayer::new_for_http());

    // the fast path has to outlive the server, and nothing of it is loaded
    // unless it was asked for
    let mut open_obj = OpenObject::new();
    let _fastpath = if args.no_fastpath {
        tracing::info!("Running without the eBPF fast path");
        None
    } else {
        let routes = fastpath_routes(assets_dir);
        Some(FastPath::attach(args.addr, &mut open_obj, routes, args.dummies).expect("attach"))
    };

    let listener = TcpListener::bind(args.addr).await.unwrap();
    let listener = BeeperListener::new(listener);
    tracing::debug!("listening on {}", listener.local_addr().unwrap());

    server::serve(listener, app).await;
}
