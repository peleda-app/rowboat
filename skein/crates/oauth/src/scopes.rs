use serde::{Deserialize, Serialize};

use crate::{OAuthError, Provider};

/// How mail is reached.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MailAccess {
    /// No mail.
    #[default]
    None,
    /// IMAP with `XOAUTH2` (and SMTP for sending).
    Imap,
    /// The provider's API: Gmail API or Microsoft Graph.
    Api,
}

/// Read only, or read and write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rw {
    /// Read only.
    Read,
    /// Read and write.
    Write,
}

/// What a sign-in grants: the domains an account syncs and whether Skein may write to them.
/// Consent can grow later (mail first, calendars later): sign in again with a wider `Access`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Access {
    /// How mail is reached.
    pub mail: MailAccess,
    /// Whether mail may be changed (flags, moves, deletes).
    #[serde(default)]
    pub mail_write: bool,
    /// Whether mail may be sent.
    #[serde(default)]
    pub send: bool,
    /// Calendars.
    #[serde(default)]
    pub calendar: Option<Rw>,
    /// Contacts.
    #[serde(default)]
    pub contacts: Option<Rw>,
}

const G: &str = "https://www.googleapis.com/auth/";
const GRAPH: &str = "https://graph.microsoft.com/";
const OUTLOOK: &str = "https://outlook.office.com/";

impl Access {
    /// Space-separated scopes for `provider`, the least that covers this access, always with a
    /// refresh token. [`OAuthError::Rejected`] for combinations a provider cannot grant in one
    /// token: Microsoft issues tokens for one resource, so IMAP cannot be combined with
    /// calendars or contacts (use the API for mail too).
    pub fn scopes(&self, provider: Provider) -> Result<String, OAuthError> {
        let mut out: Vec<String> = Vec::new();
        match provider {
            Provider::Google => {
                match self.mail {
                    MailAccess::None if self.send => out.push(format!("{G}gmail.send")),
                    MailAccess::None => {}
                    MailAccess::Imap => out.push("https://mail.google.com/".into()),
                    MailAccess::Api => {
                        out.push(format!(
                            "{G}{}",
                            if self.mail_write {
                                "gmail.modify"
                            } else {
                                "gmail.readonly"
                            }
                        ));
                        if self.send {
                            out.push(format!("{G}gmail.send"));
                        }
                    }
                }
                match self.calendar {
                    Some(Rw::Read) => out.push(format!("{G}calendar.readonly")),
                    Some(Rw::Write) => out.push(format!("{G}calendar")),
                    None => {}
                }
                match self.contacts {
                    Some(Rw::Read) => out.push(format!("{G}contacts.readonly")),
                    Some(Rw::Write) => out.push(format!("{G}contacts")),
                    None => {}
                }
            }
            Provider::Microsoft => {
                match self.mail {
                    MailAccess::Imap => {
                        if self.calendar.is_some() || self.contacts.is_some() {
                            return Err(OAuthError::Rejected(
                                "Microsoft cannot grant IMAP together with calendars or contacts; use the API for mail".into(),
                            ));
                        }
                        out.push(format!("{OUTLOOK}IMAP.AccessAsUser.All"));
                        if self.send {
                            out.push(format!("{OUTLOOK}SMTP.Send"));
                        }
                    }
                    MailAccess::Api => {
                        out.push(format!(
                            "{GRAPH}{}",
                            if self.mail_write {
                                "Mail.ReadWrite"
                            } else {
                                "Mail.Read"
                            }
                        ));
                        if self.send {
                            out.push(format!("{GRAPH}Mail.Send"));
                        }
                    }
                    MailAccess::None if self.send => out.push(format!("{GRAPH}Mail.Send")),
                    MailAccess::None => {}
                }
                match self.calendar {
                    Some(Rw::Read) => out.push(format!("{GRAPH}Calendars.Read")),
                    Some(Rw::Write) => out.push(format!("{GRAPH}Calendars.ReadWrite")),
                    None => {}
                }
                match self.contacts {
                    Some(Rw::Read) => out.push(format!("{GRAPH}Contacts.Read")),
                    Some(Rw::Write) => out.push(format!("{GRAPH}Contacts.ReadWrite")),
                    None => {}
                }
                if out.iter().any(|s| s.starts_with(GRAPH)) {
                    out.push(format!("{GRAPH}User.Read"));
                }
                if !out.is_empty() {
                    out.push("offline_access".into());
                }
            }
        }
        if out.is_empty() {
            return Err(OAuthError::Rejected("the access asks for nothing".into()));
        }
        Ok(out.join(" "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn access(mail: MailAccess, write: bool, send: bool) -> Access {
        Access {
            mail,
            mail_write: write,
            send,
            ..Default::default()
        }
    }

    #[test]
    fn google_asks_for_the_least_that_covers_the_access() {
        assert_eq!(
            access(MailAccess::Api, false, false)
                .scopes(Provider::Google)
                .unwrap(),
            "https://www.googleapis.com/auth/gmail.readonly"
        );
        assert_eq!(
            access(MailAccess::Api, true, true)
                .scopes(Provider::Google)
                .unwrap(),
            "https://www.googleapis.com/auth/gmail.modify https://www.googleapis.com/auth/gmail.send"
        );
        assert_eq!(
            access(MailAccess::Imap, false, true)
                .scopes(Provider::Google)
                .unwrap(),
            "https://mail.google.com/"
        );
        let all = Access {
            mail: MailAccess::Api,
            mail_write: true,
            send: false,
            calendar: Some(Rw::Read),
            contacts: Some(Rw::Write),
        };
        assert_eq!(
            all.scopes(Provider::Google).unwrap(),
            "https://www.googleapis.com/auth/gmail.modify https://www.googleapis.com/auth/calendar.readonly https://www.googleapis.com/auth/contacts"
        );
    }

    #[test]
    fn microsoft_scopes_stay_on_one_resource() {
        assert_eq!(
            access(MailAccess::Api, true, true)
                .scopes(Provider::Microsoft)
                .unwrap(),
            "https://graph.microsoft.com/Mail.ReadWrite https://graph.microsoft.com/Mail.Send https://graph.microsoft.com/User.Read offline_access"
        );
        assert_eq!(
            access(MailAccess::Imap, false, true)
                .scopes(Provider::Microsoft)
                .unwrap(),
            "https://outlook.office.com/IMAP.AccessAsUser.All https://outlook.office.com/SMTP.Send offline_access"
        );
        let mixed = Access {
            mail: MailAccess::Imap,
            calendar: Some(Rw::Read),
            ..Default::default()
        };
        assert!(mixed.scopes(Provider::Microsoft).is_err());
        assert!(Access::default().scopes(Provider::Google).is_err());
    }
}
