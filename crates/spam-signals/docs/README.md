# rowboat-spam-signals

`rowboat-spam` from signals the node already has, in this order:

1. the provider put the message in a junk-role mailbox: `Junk`;
2. no `Authentication-Results` field at position 0 (the topmost, added last by the receiving server): `NotChecked`;
3. that field says `dmarc=fail`: `Suspicious`; `dmarc=pass`: `Clean`;
4. it has DKIM or SPF passes and none is for the `From` domain, a parent of it or a subdomain of it (label-wise, so `evilexample.com` is not `example.com`): `Suspicious`;
5. several `From` addresses: `Suspicious`;
6. otherwise `Clean`.

A `Clean` from a field whose authserv-id is not one of the account's receivers (`SpamInput::receivers`, the domain itself or a label-wise subdomain) becomes `NotChecked`: many servers add no field, and then position 0 is whatever the sender wrote. `Suspicious` stays whoever wrote the field. `receivers_for(imap_host, address)` gives the receivers: the IMAP host without its first label when it has three or more, the address's domain, and the receiving domains of a few large providers (Gmail `google.com`, Outlook `outlook.com`, Fastmail `messagingengine.com`, iCloud, Yahoo); IP addresses, single labels and public second-level suffixes such as `co.uk` are left out.

Fields below position 0 can be written by the sender and are never read, so a forged result can only lower a verdict, never raise trust. Version `signals-2`; bump `VERSION` with any change to these rules.

Runs `rowboat_spam::testing::filter` over rinse's hostile corpus rendered with `rinse-mail-direct`, plus tests of each rule, of a forged pass below the receiver's field, of a pass from a server that is not the receiver, and of `receivers_for`.
