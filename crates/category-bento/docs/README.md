# rowboat-category-bento

`rowboat-category` over bento's standard analyzer (`bento::standard()`).

- **Input.** A bento `MessageInput` built from the rendered message: the subject (control characters replaced, at most 1,000 characters), the text body split into paragraphs at blank lines (at most 512 blocks of at most 16 KiB, 128 KiB in all), and the single `From` address with its domain and display name. Links, list facts, authentication and structured data are left empty in phase 1; the insight layer's full adapter comes with notifications (rowboat phase 4).
- **Output.** The primary class when its confidence is `Likely` or better and it is not `unknown`; `None` otherwise, and `None` when bento's `verify` refuses the input.
- **Version.** `bento-` and bento's analyzer version, cleaned to `[a-z0-9._-]` and cut to 64 characters, so a new bento build re-parses messages lazily.

Runs `rowboat_category::testing::categorizer` over rinse's hostile corpus rendered with `rinse-mail-direct`, plus a test that inputs stay within bento's caps.
