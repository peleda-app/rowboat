//! The small version in `cargo test`: invariants only, no timing targets.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_small_load_syncs_everything_and_settles() {
    let r = rowboat_load::run(300, 3, 60, 400).await.unwrap();
    assert_eq!(r.messages, 300);
    assert_eq!(r.marked, 60);
    assert!(r.rate > 0.0);
}
