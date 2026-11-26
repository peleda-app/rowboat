//! Entry points for the fuzz targets in `fuzz/`. Not part of the public API.

use url::Url;

use crate::xml::{self, CALDAV, DAV, Element};
use crate::{etag, ok_props, path, prop, read_only, schedule};

fn decoded_len(e: &Element) -> usize {
    e.text.len()
        + e.attrs.iter().map(|(_, v)| v.len()).sum::<usize>()
        + e.children.iter().map(decoded_len).sum::<usize>()
}

/// Reads `bytes` as a WebDAV answer the way a session does: the tree, then every response's
/// href, status, properties, ETag, privileges, component set and principal addresses.
pub fn multistatus(bytes: &[u8]) {
    let Some(root) = xml::parse(bytes) else {
        return;
    };
    assert!(
        decoded_len(&root) <= bytes.len(),
        "text grew while parsing: an entity was expanded"
    );
    let base = Url::parse("https://dav.example.com/calendars/ada/").expect("a valid base");
    for response in root.children(DAV, "response") {
        let _ = xml::status_code(response.child(DAV, "status"));
        let props = ok_props(response);
        let _ = etag(&props);
        let _ = read_only(&props);
        let _ = schedule::addresses(&props);
        if let Some(set) = prop(&props, CALDAV, "supported-calendar-component-set") {
            let _: Vec<String> = set
                .children(CALDAV, "comp")
                .filter_map(|c| c.attr("name"))
                .map(str::to_ascii_uppercase)
                .collect();
        }
        let _ = props.iter().find_map(|p| p.child_named("calendar-color"));
        if let Some(at) = response
            .child(DAV, "href")
            .and_then(Element::trimmed)
            .and_then(|h| base.join(h).ok())
        {
            let id = path::id(&at);
            let _ = path::last_segment(&id);
            assert_eq!(path::decode(&path::encode(&id)), id);
        }
    }
    let _ = root.child(DAV, "sync-token").and_then(Element::trimmed);
    let _ = root
        .child(DAV, "response")
        .map(ok_props)
        .and_then(|props| props.iter().find_map(|p| p.child_named("getctag")))
        .and_then(Element::trimmed)
        .map(str::to_owned);
}
