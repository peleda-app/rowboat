use std::future::Future;
use std::sync::Mutex;

use tokio::task::JoinHandle;

/// Tasks that hold a node's pieces beyond the call that started them, ended together on shutdown.
#[derive(Default)]
pub(crate) struct Background(Mutex<Vec<JoinHandle<()>>>);

impl Background {
    pub(crate) fn spawn(&self, task: impl Future<Output = ()> + Send + 'static) {
        self.push(tokio::spawn(task));
    }

    pub(crate) fn push(&self, task: JoinHandle<()>) {
        let mut tasks = self.0.lock().unwrap_or_else(|e| e.into_inner());
        tasks.retain(|t| !t.is_finished());
        tasks.push(task);
    }

    /// Aborts every task and returns once each has been dropped, with everything it held.
    pub(crate) async fn stop(&self) {
        let tasks = std::mem::take(&mut *self.0.lock().unwrap_or_else(|e| e.into_inner()));
        for t in &tasks {
            t.abort();
        }
        for t in tasks {
            let _ = t.await;
        }
    }
}

/// Waits for `task` up to `limit`, then aborts it; returns once it has been dropped either way.
pub(crate) async fn join_within(mut task: JoinHandle<()>, limit: std::time::Duration) {
    if tokio::time::timeout(limit, &mut task).await.is_err() {
        task.abort();
        let _ = task.await;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn stopping_drops_what_every_task_held() {
        let piece = Arc::new(());
        let background = Background::default();
        for _ in 0..3 {
            let held = piece.clone();
            background.spawn(async move {
                std::future::pending::<()>().await;
                drop(held);
            });
        }
        background.spawn(async {});
        tokio::task::yield_now().await;
        assert_eq!(Arc::strong_count(&piece), 4);
        background.stop().await;
        assert_eq!(Arc::strong_count(&piece), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_task_past_its_limit_is_dropped_before_join_returns() {
        let piece = Arc::new(());
        let held = piece.clone();
        let task = tokio::spawn(async move {
            std::future::pending::<()>().await;
            drop(held);
        });
        join_within(task, Duration::from_secs(30)).await;
        assert_eq!(Arc::strong_count(&piece), 1);
        let done = tokio::spawn(async {});
        join_within(done, Duration::from_secs(30)).await;
    }
}
