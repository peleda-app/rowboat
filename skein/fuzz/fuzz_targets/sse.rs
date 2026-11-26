#![no_main]

use libfuzzer_sys::fuzz_target;
use skein_sse::{Event, Parser, TooLarge};

const LIMIT: usize = 512;

fn whole(stream: &[u8]) -> Result<Vec<Event>, TooLarge> {
    Parser::new(LIMIT).push(stream)
}

fn chunked(stream: &[u8], cuts: &[u8]) -> Result<Vec<Event>, TooLarge> {
    let mut parser = Parser::new(LIMIT);
    let mut events = Vec::new();
    let mut rest = stream;
    for &cut in cuts {
        let at = (cut as usize).min(rest.len());
        let (head, tail) = rest.split_at(at);
        events.extend(parser.push(head)?);
        rest = tail;
    }
    events.extend(parser.push(rest)?);
    Ok(events)
}

fuzz_target!(|data: &[u8]| {
    let split = data
        .first()
        .map_or(0, |&n| (n as usize % 16).min(data.len() - 1));
    let (cuts, stream) = data[1.min(data.len())..].split_at(split);
    let at_once = whole(stream);
    if let Ok(events) = &at_once {
        for event in events {
            assert!(event.data.len() <= LIMIT);
            assert!(!event.event.is_empty());
        }
    }
    assert_eq!(
        at_once,
        chunked(stream, cuts),
        "chunk boundaries never change the events"
    );
});
