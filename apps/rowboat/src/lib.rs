//! `rowboat`, Peleda's headless multi-tenant server (GROUP.md, "The headless server"): one
//! process per host, one node per tenant composed by `rowboat-node`, each the server node of one
//! person's group. A tenant is created by a server invite, bound to the genesis of the group
//! whose device adopted it, and served to that group only. There is no management API: the
//! operator has the command line ([`cli`]), the owner the app.

pub mod cli;
pub mod config;
pub mod endpoints;
pub mod host;
pub mod qr;
pub mod tenant;
