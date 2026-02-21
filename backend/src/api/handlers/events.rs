use axum::{
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
    routing::get,
    Router,
};
use futures::stream::Stream;
use std::convert::Infallible;
use tokio::sync::broadcast;

use crate::api::SharedState;
use crate::error::Result;

pub fn router() -> Router<SharedState> {
    Router::new().route("/stream", get(event_stream))
}

/// Stream domain events via Server-Sent Events.
///
/// Clients receive `entity.changed` events whenever a CRUD operation happens.
/// If a client falls behind, it receives a `lagged` event and should do a full refresh.
#[utoipa::path(
    get,
    path = "/stream",
    context_path = "/api/v1/events",
    tag = "events",
    responses(
        (status = 200, description = "SSE stream of domain events")
    ),
    security(("bearer_auth" = []))
)]
async fn event_stream(
    State(state): State<SharedState>,
) -> Result<Sse<impl Stream<Item = std::result::Result<Event, Infallible>>>> {
    let mut rx = state.event_bus.subscribe();

    let stream = async_stream::stream! {
        yield Ok(Event::default().event("connected").data(r#"{"status":"ok"}"#));

        loop {
            match rx.recv().await {
                Ok(domain_event) => {
                    let data = serde_json::to_string(&domain_event).unwrap_or_default();
                    yield Ok(Event::default().event("entity.changed").data(data));
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    yield Ok(Event::default()
                        .event("lagged")
                        .data(format!(r#"{{"missed":{n}}}"#)));
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    };

    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(std::time::Duration::from_secs(15))
            .text("ping"),
    ))
}
