//! Cancellation at CLI operation boundaries, including headless Windows processes.
use crate::{Error, Result};

pub async fn signal() {
    if tokio::signal::ctrl_c().await.is_err() {
        // Detached Windows processes may have no console handler. They must still
        // complete normally; unavailable cancellation is not an operation failure.
        std::future::pending::<()>().await;
    }
}

pub async fn run<T>(operation: impl std::future::Future<Output = Result<T>>) -> Result<T> {
    tokio::select! {
        // Register the OS handler before an operation can launch a browser or
        // dispatch a request that makes cancellation observable to its caller.
        biased;
        _ = signal() => Err(Error::new("interrupted", "Operation interrupted")),
        result = operation => result,
    }
}
