use baton_core::ResourceId;

/// The resource kind of a mail account (GROUP.md, "Resources, capabilities and command classes").
pub const ACCOUNT_KIND: &str = "peleda.mail-account";

/// The resource of a mail account: `acct-{account}`. `None` when the account id does not fit a
/// resource id.
pub fn account_resource(account: &str) -> Option<ResourceId> {
    ResourceId::new(format!("acct-{account}")).ok()
}

/// The resource of a node: `node-{node id}`.
pub fn node_resource(node: &str) -> Option<ResourceId> {
    ResourceId::new(format!("node-{node}")).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_ids_fit() {
        let account = format!("a{}", "q".repeat(26));
        assert_eq!(
            account_resource(&account).unwrap().as_str(),
            format!("acct-{account}")
        );
        let node = "a".repeat(52);
        assert!(node_resource(&node).is_some());
        assert!(account_resource("Bad/Id").is_none());
        assert!(account_resource(&"a".repeat(60)).is_none());
    }
}
