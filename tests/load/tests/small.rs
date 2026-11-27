//! The small version in `cargo test`: invariants only, no timing targets.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_small_load_syncs_everything_and_settles() {
    let r = rowboat_load::run(300, 3, 60, 400).await.unwrap();
    assert_eq!(r.messages, 300);
    assert_eq!(r.marked, 60);
    assert!(r.rate > 0.0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_small_replication_reaches_the_second_node_and_settles() {
    let r = rowboat_load::replicate(200, 2, 40, 300).await.unwrap();
    assert_eq!(r.messages, 200);
    assert_eq!(r.marked, 40);
    assert!(r.rate > 0.0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_small_handover_moves_every_account_to_the_server() {
    let r = rowboat_load::handover(6, 5).await.unwrap();
    assert_eq!(r.accounts, 6);
    assert_eq!(r.messages, 30);
}
