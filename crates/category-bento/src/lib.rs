//! Categories from bento's standard analyzer.
//!
//! Builds a bento `MessageInput` from the subject, the text body (split into paragraphs) and the
//! single `From` address of a rendered message, runs `bento::standard()` and answers with the
//! primary class when it is `Likely` or better and not `unknown`. Input that bento's `verify`
//! refuses gives `None`. Nothing else of bento (codes, links, insights) is used.

use bento::{Analyzer, Confidence, MessageInput, Sender, TextBlock};
use rowboat_category::{Categorizer, Category, CategoryInput};

const MAX_SUBJECT_CHARS: usize = 1_000;
const MAX_BLOCKS: usize = 512;
const MAX_BLOCK_BYTES: usize = 16 * 1024;
const MAX_TEXT_BYTES: usize = 128 * 1024;

/// bento's standard analyzer behind the category contract.
pub struct BentoCategorizer {
    analyzer: Analyzer,
    version: String,
}

/// Why the categorizer could not be built: bento's embedded tables did not load.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unavailable;

impl BentoCategorizer {
    /// The categorizer over `bento::standard()`.
    pub fn new() -> Result<Self, Unavailable> {
        let analyzer = bento::standard().map_err(|_| Unavailable)?;
        let version = version_of(&analyzer.version());
        Ok(Self { analyzer, version })
    }

    /// The bento input built from a rendered message, as [`Categorizer::category`] analyzes it.
    pub fn input_of(rendered: &rinse_mail::Rendered) -> MessageInput {
        let subject: String = rendered
            .headers
            .subject
            .as_deref()
            .unwrap_or_default()
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .take(MAX_SUBJECT_CHARS)
            .collect();
        let mut blocks = Vec::new();
        let mut total = 0;
        for para in rendered.text.split("\n\n") {
            let text = cut(para.trim(), MAX_BLOCK_BYTES);
            if text.is_empty() {
                continue;
            }
            if blocks.len() == MAX_BLOCKS || total + text.len() > MAX_TEXT_BYTES {
                break;
            }
            total += text.len();
            blocks.push(TextBlock {
                text: text
                    .chars()
                    .map(|c| {
                        if c.is_control() && c != '\n' && c != '\t' {
                            ' '
                        } else {
                            c
                        }
                    })
                    .collect(),
                ..TextBlock::default()
            });
        }
        let sender = match rendered.headers.from.as_slice() {
            [one] => {
                let address = one.address.to_ascii_lowercase();
                let domain = address.rsplit_once('@').map(|(_, d)| d.to_owned());
                Sender {
                    address: Some(address),
                    display_name: one.name.clone(),
                    domain,
                    ..Sender::default()
                }
            }
            _ => Sender::default(),
        };
        MessageInput {
            subject,
            blocks,
            sender,
            ..MessageInput::default()
        }
    }
}

fn cut(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

fn version_of(analyzer: &str) -> String {
    let clean: String = analyzer
        .chars()
        .map(|c| match c {
            'a'..='z' | '0'..='9' | '.' | '_' | '-' => c,
            'A'..='Z' => c.to_ascii_lowercase(),
            _ => '-',
        })
        .collect();
    let mut v = format!("bento-{clean}");
    v.truncate(64);
    v
}

impl Categorizer for BentoCategorizer {
    fn category(&self, input: &CategoryInput<'_>) -> Option<Category> {
        let message = Self::input_of(input.rendered);
        if bento::verify(&message).is_err() {
            return None;
        }
        let analysis = self.analyzer.analyze(&message);
        let primary = analysis.primary;
        if primary.confidence < Confidence::Likely || primary.class == bento::ClassId::unknown() {
            return None;
        }
        Category::new(primary.class.as_str())
    }

    fn version(&self) -> String {
        self.version.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bytes::Bytes;
    use rinse_mail::{Content, ContentLimits, RenderOptions, RenderRequest, Rendered};
    use rinse_mail_direct::DirectContent;

    use super::*;

    async fn render(raw: &[u8]) -> Option<Rendered> {
        let content: Arc<dyn Content> = Arc::new(DirectContent::new());
        content
            .render(RenderRequest {
                raw: Bytes::copy_from_slice(raw),
                options: RenderOptions::default(),
                limits: ContentLimits::default(),
            })
            .await
            .ok()
    }

    #[tokio::test]
    async fn conformance_over_the_hostile_corpus() {
        let c = BentoCategorizer::new().unwrap();
        let mut rendered = Vec::new();
        for f in rinse_mail::testing::CORPUS {
            if let Some(r) = render(f.raw).await {
                rendered.push(r);
            }
        }
        rowboat_category::testing::categorizer(&c, &rendered);
    }

    #[tokio::test]
    async fn inputs_stay_within_bentos_caps() {
        let body = "word ".repeat(200_000);
        let raw = format!(
            "From: Pat <PAT@Example.COM>\r\nSubject: Line\x07one\r\n\r\n{body}\r\n\r\nsecond\r\n"
        );
        let r = render(raw.as_bytes()).await.unwrap();
        let input = BentoCategorizer::input_of(&r);
        assert!(input.blocks.iter().map(|b| b.text.len()).sum::<usize>() <= MAX_TEXT_BYTES);
        assert_eq!(input.sender.address.as_deref(), Some("pat@example.com"));
        assert_eq!(input.sender.domain.as_deref(), Some("example.com"));
        assert!(!input.subject.chars().any(char::is_control));
        let c = BentoCategorizer::new().unwrap();
        let _ = c.category(&CategoryInput {
            rendered: &r,
            account: "a",
        });
        assert!(rowboat_category::valid_version(&c.version()));
    }

    #[test]
    fn versions_are_cleaned() {
        assert_eq!(version_of("Run 1/2"), "bento-run-1-2");
        assert!(version_of(&"x".repeat(200)).len() <= 64);
    }
}
