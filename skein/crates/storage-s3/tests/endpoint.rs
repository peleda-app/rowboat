//! The conformance suite against a real S3-compatible endpoint, such as RustFS or the Versity S3 Gateway in a local
//! container. Runs only with `SKEIN_IT=1` and the `SKEIN_IT_S3_*` variables set.

use std::sync::Arc;

use skein_storage_s3::{S3Config, S3Objects};

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

#[tokio::test]
async fn conformance_against_a_real_endpoint() {
    let vars = (
        env("SKEIN_IT").filter(|v| v == "1"),
        env("SKEIN_IT_S3_ENDPOINT"),
        env("SKEIN_IT_S3_BUCKET"),
        env("SKEIN_IT_S3_ACCESS_KEY"),
        env("SKEIN_IT_S3_SECRET_KEY"),
    );
    let (Some(_), Some(endpoint), Some(bucket), Some(access_key_id), Some(secret_access_key)) =
        vars
    else {
        eprintln!(
            "skipped: set SKEIN_IT=1 and SKEIN_IT_S3_ENDPOINT, SKEIN_IT_S3_BUCKET, \
             SKEIN_IT_S3_ACCESS_KEY, SKEIN_IT_S3_SECRET_KEY to run against a real endpoint"
        );
        return;
    };
    let config = S3Config {
        endpoint: Some(endpoint),
        bucket,
        region: env("SKEIN_IT_S3_REGION").unwrap_or_else(|| "us-east-1".into()),
        prefix: Some(format!("skein-it/{}", ulid::Ulid::generate())),
        access_key_id,
        secret_access_key,
        allow_http: true,
    };
    let store = S3Objects::new(&config).expect("valid config");
    skein_storage::testing::all_over_objects(Arc::new(store)).await;
}
