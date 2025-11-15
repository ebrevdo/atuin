use std::time::Duration;

use eyre::{Result, WrapErr};
use tokio::runtime::{Builder, Runtime};

const SHUTDOWN_TIMEOUT_MS: u64 = 50;

pub struct CliRuntime {
    inner: Option<Runtime>,
}

impl CliRuntime {
    pub fn new_current_thread() -> Result<Self> {
        let inner = Builder::new_current_thread()
            .enable_all()
            .build()
            .wrap_err("failed to start runtime")?;

        Ok(Self { inner: Some(inner) })
    }

    pub fn block_on<F>(&self, future: F) -> F::Output
    where
        F: std::future::Future,
    {
        self.inner
            .as_ref()
            .expect("runtime should exist")
            .block_on(future)
    }
}

impl Drop for CliRuntime {
    fn drop(&mut self) {
        if let Some(runtime) = self.inner.take() {
            runtime.shutdown_timeout(Duration::from_millis(SHUTDOWN_TIMEOUT_MS));
        }
    }
}
