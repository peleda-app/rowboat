#![no_main]

use libfuzzer_sys::fuzz_target;
use skein_push::{
    MAX_GRAPH_ITEMS, MAX_VALIDATION_TOKEN, parse_gmail, parse_graph, validation_token,
};

fuzz_target!(|data: &[u8]| {
    if let Ok(items) = parse_graph(data) {
        assert!(items.len() <= MAX_GRAPH_ITEMS);
        for item in items {
            assert!(!item.subscription_id.is_empty() && item.subscription_id.len() <= 128);
        }
    }
    if let Ok(notification) = parse_gmail(data) {
        assert!(notification.email.contains('@'));
        assert!(notification.email.len() <= 320);
        assert_eq!(notification.email.trim(), notification.email);
    }
    let text = String::from_utf8_lossy(data);
    if let Some(token) = validation_token(&text) {
        assert!(!token.is_empty() && token.len() <= MAX_VALIDATION_TOKEN);
        assert!(token.bytes().all(|b| (0x20..0x7f).contains(&b)));
    }
});
