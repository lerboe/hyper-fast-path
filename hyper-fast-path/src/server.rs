//! The server's connection loop.
//!
//! HTTP/2 is driven through the [`h2`] crate directly rather than through
//! `axum::serve`, because the dynamic table updates the fast path sends have to
//! be applied to the connection's HPACK decoder between requests, and the only
//! thing that owns that decoder is the [`h2::server::Connection`]. Reaching it
//! through `axum::serve` would mean reaching through hyper, which does not hand
//! it out; owning the connection here is what makes
//! [`Connection::prime_dynamic_table`] (see the patched `vendor/h2`) reachable.
//!
//! The application itself is still an ordinary [`axum::Router`]: requests are
//! translated into what it expects and its responses are written back onto the
//! stream.

use crate::listener::{BeeperListener, BeeperStream, FlowHandle, Protocol, SyncHandle};
use axum::{Router, body::Body, extract::Request};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::{convert::Infallible, future::poll_fn, task::Poll};
use tower::ServiceExt;
use tracing::{debug, error};

/// Serves `app` on `listener` until the process is stopped.
pub async fn serve(listener: BeeperListener, app: Router) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                error!("failed to accept a connection: {e}");
                continue;
            }
        };

        let app = app.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_connection(stream, app).await {
                debug!("connection from {peer} ended: {e}");
            }
        });
    }
}

/// Serves a single connection, in whichever protocol it turns out to speak.
async fn serve_connection(mut stream: BeeperStream, app: Router) -> anyhow::Result<()> {
    let sync = stream.sync_handle();
    let flow = stream.flow_handle();

    match stream.protocol().await? {
        Protocol::Http2 => serve_h2(stream, sync, flow, app).await,
        Protocol::Http1 => serve_h1(stream, app).await,
    }
}

/// Serves an HTTP/1.1 connection, which needs none of the dynamic table
/// handling: HTTP/1.1 spells its headers out, so nothing the fast path answers
/// can leave the server out of step.
async fn serve_h1(stream: BeeperStream, app: Router) -> anyhow::Result<()> {
    let service = service_fn(move |req: Request<hyper::body::Incoming>| {
        let app = app.clone();
        async move {
            let req = req.map(Body::new);
            app.oneshot(req).await
        }
    });

    hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(stream), service)
        .await?;

    Ok(())
}

/// Serves an HTTP/2 connection, applying the fast path's dynamic table updates
/// and the window it spent as they arrive.
async fn serve_h2(
    stream: BeeperStream,
    sync: SyncHandle,
    flow: FlowHandle,
    app: Router,
) -> anyhow::Result<()> {
    let mut conn = h2::server::handshake(stream).await?;

    loop {
        // the stream withholds everything behind an update until it has been
        // taken, so this has to run before every poll of the connection: it is
        // both what applies the update and what lets the request it belongs to
        // through. see `SyncHandle::take`.
        let accepted = poll_fn(|cx| {
            // the fast path has already spent this much of the client's
            // connection window, so h2 has to stop counting it as its own
            // before it hands out any more capacity
            let sent = flow.take();
            if sent > 0 {
                debug!("taking {sent}B served out of band out of the send window");

                if let Err(e) = conn.consume_send_capacity(sent) {
                    return Poll::Ready(Some(Err(anyhow::anyhow!(
                        "failed to account for {sent}B served out of band: {e:?}"
                    ))));
                }
            }

            for block in sync.take() {
                debug!("applying a {}B dynamic table update", block.len());

                if let Err(e) = conn.prime_dynamic_table(&block) {
                    // carrying on would decode every later request against a
                    // table that no longer matches the client's, so the
                    // connection ends here rather than serving nonsense
                    return Poll::Ready(Some(Err(anyhow::anyhow!(
                        "failed to apply a {}B dynamic table update: {e:?}",
                        block.len()
                    ))));
                }
            }

            conn.poll_accept(cx)
                .map(|res| res.map(|res| res.map_err(anyhow::Error::from)))
        })
        .await;

        let Some(accepted) = accepted else {
            return Ok(());
        };

        let (req, mut respond) = accepted?;
        let app = app.clone();

        tokio::spawn(async move {
            if let Err(e) = respond_to(req, &mut respond, app).await {
                debug!("failed to respond: {e}");
            }
        });
    }
}

/// Hands `req` to `app` and writes its response back onto the stream.
async fn respond_to(
    req: http::Request<h2::RecvStream>,
    respond: &mut h2::server::SendResponse<Bytes>,
    app: Router,
) -> anyhow::Result<()> {
    let (parts, mut body) = req.into_parts();

    // the fast path's routes are all GETs, so a request body is collected in
    // one go rather than streamed through
    let mut collected = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        let _ = body.flow_control().release_capacity(chunk.len());
        collected.extend_from_slice(&chunk);
    }

    let req = Request::from_parts(parts, Body::from(collected));
    let res: http::Response<Body> = app
        .oneshot(req)
        .await
        .unwrap_or_else(|e: Infallible| match e {});

    let (parts, body) = res.into_parts();
    let body = body.collect().await?.to_bytes();

    let res = http::Response::from_parts(parts, ());
    let mut send = respond.send_response(res, body.is_empty())?;
    if !body.is_empty() {
        send.send_data(body, true)?;
    }

    Ok(())
}
