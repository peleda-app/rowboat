use skein_core::CollectionKind;
use skein_pim::PimError;
use url::Url;

use crate::http::MAX_XML;
use crate::xml::{CALDAV, DAV, Element};
use crate::{DavSession, ok_props, prop};

/// What the calendar user's principal says about scheduling (RFC 6638 section 2).
#[derive(Debug, Clone, Default)]
pub(crate) struct Principal {
    /// `calendar-user-address-set` entries that are `mailto:` addresses, lower case.
    pub addresses: Vec<String>,
    /// The scheduling inbox, on the account's own origin.
    pub inbox: Option<Url>,
}

const PROPS: &str = "<d:current-user-principal/><cal:calendar-user-address-set/>\
                     <cal:schedule-inbox-URL/>";

/// The `mailto:` entries of `calendar-user-address-set`, lower case, each once.
pub(crate) fn addresses(props: &[&Element]) -> Vec<String> {
    let mut addresses = Vec::new();
    if let Some(set) = prop(props, CALDAV, "calendar-user-address-set") {
        for href in set.children(DAV, "href").filter_map(Element::trimmed) {
            if href.len() > 7
                && href
                    .get(..7)
                    .is_some_and(|s| s.eq_ignore_ascii_case("mailto:"))
            {
                let a = skein_itip::address(href);
                if a.contains('@') && !addresses.contains(&a) {
                    addresses.push(a);
                }
            }
        }
    }
    addresses
}

fn read(response: &Element, base: &Url, session: &DavSession) -> Principal {
    let props = ok_props(response);
    let addresses = addresses(&props);
    let inbox = prop(&props, CALDAV, "schedule-inbox-URL")
        .and_then(|p| p.child(DAV, "href"))
        .and_then(Element::trimmed)
        .and_then(|h| base.join(h).ok())
        .filter(|u| session.inner.http.may_sign_in(u));
    Principal { addresses, inbox }
}

fn quiet(e: PimError) -> Result<Option<(Element, Url)>, PimError> {
    match e {
        PimError::NotFound | PimError::Protocol(_) => Ok(None),
        other => Err(other),
    }
}

impl DavSession {
    /// The principal's scheduling properties, read once per session; empty when no calendars
    /// are configured or the server does not say.
    pub(crate) async fn principal(&mut self) -> Result<&Principal, PimError> {
        if self.principal.is_none() {
            let found = self.find_principal().await?;
            tracing::debug!(
                addresses = found.addresses.len(),
                inbox = found.inbox.is_some(),
                "DAV principal read"
            );
            self.principal = Some(found);
        }
        Ok(self.principal.as_ref().expect("just set"))
    }

    async fn find_principal(&self) -> Result<Principal, PimError> {
        let Some(configured) = self.inner.calendars.clone() else {
            return Ok(Principal::default());
        };
        let url = self.resolve(CollectionKind::Calendar, &configured).await?;
        let Some((root, base)) = self
            .propfind(&url, "0", PROPS)
            .await
            .map(Some)
            .or_else(quiet)?
        else {
            return Ok(Principal::default());
        };
        let Some(response) = root.child(DAV, "response") else {
            return Ok(Principal::default());
        };
        let here = read(response, &base, self);
        if !here.addresses.is_empty() {
            return Ok(here);
        }
        let Some(principal) = prop(&ok_props(response), DAV, "current-user-principal")
            .and_then(|p| p.child(DAV, "href"))
            .and_then(Element::trimmed)
            .and_then(|h| base.join(h).ok())
            .filter(|u| self.inner.http.may_sign_in(u))
        else {
            return Ok(here);
        };
        let Some((root, base)) = self
            .propfind(&principal, "0", PROPS)
            .await
            .map(Some)
            .or_else(quiet)?
        else {
            return Ok(here);
        };
        Ok(root
            .child(DAV, "response")
            .map(|r| read(r, &base, self))
            .unwrap_or(here))
    }

    /// Whether the server schedules writes to the calendar at `url`: its `OPTIONS` answer lists
    /// `calendar-auto-schedule` in the `DAV` header (RFC 6638 section 2). Asked once per
    /// calendar and session.
    pub(crate) async fn auto_schedules(&mut self, url: &Url) -> Result<bool, PimError> {
        if let Some(known) = self.auto.get(url.as_str()) {
            return Ok(*known);
        }
        let answer = self
            .inner
            .http
            .request("OPTIONS", url, None, None, &[], MAX_XML)
            .await?;
        let auto = answer.status.is_success()
            && answer.headers.get_all("dav").iter().any(|v| {
                v.to_str().is_ok_and(|v| {
                    v.split(',')
                        .any(|t| t.trim().eq_ignore_ascii_case("calendar-auto-schedule"))
                })
            });
        tracing::debug!(auto, "DAV scheduling checked");
        self.auto.insert(url.as_str().to_owned(), auto);
        Ok(auto)
    }
}
